using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using IdentityServer.Configurations;
using IdentityServer.Data;
using IdentityServer.Data.Models;
using IdentityServer.Services;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IdentityServer.Endpoints;

public static class CustomIdentityDefaultApi
{
    private static readonly EmailAddressAttribute _emailAddressAttribute = new();

    public static IEndpointConventionBuilder MapCustomIdentityApi<TUser>(this IEndpointRouteBuilder endpoints,
        params string[] exclude)
        where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);

        var timeProvider = endpoints.ServiceProvider.GetRequiredService<TimeProvider>();
        var bearerTokenOptions = endpoints.ServiceProvider.GetRequiredService<IOptionsMonitor<BearerTokenOptions>>();
        var emailSender = endpoints.ServiceProvider.GetRequiredService<IEmailSender<TUser>>();
        var linkGenerator = endpoints.ServiceProvider.GetRequiredService<LinkGenerator>();

        // We'll figure out a unique endpoint name based on the final route pattern during endpoint generation.
        string? confirmEmailEndpointName = null;

        var routeGroup = endpoints.MapGroup("");

        // NOTE: We cannot inject UserManager<TUser> directly because the TUser generic parameter is currently unsupported by RDG.
        // https://github.com/dotnet/aspnetcore/issues/47338
        if (!exclude.Contains(IdentityApiEndpointPath.Register))
            routeGroup.MapPost($"/{IdentityApiEndpointPath.Register}", async Task<Results<Ok, ValidationProblem>>
                ([FromBody] RegisterRequest registration, HttpContext context, [FromServices] IServiceProvider sp) =>
            {
                var userManager = sp.GetRequiredService<UserManager<TUser>>();

                if (!userManager.SupportsUserEmail)
                {
                    throw new NotSupportedException(
                        $"{nameof(MapCustomIdentityApi)} requires a user store with email support.");
                }

                var userStore = sp.GetRequiredService<IUserStore<TUser>>();
                var emailStore = (IUserEmailStore<TUser>)userStore;
                var email = registration.Email;

                if (string.IsNullOrEmpty(email) || !_emailAddressAttribute.IsValid(email))
                {
                    return CreateValidationProblem(
                        IdentityResult.Failed(userManager.ErrorDescriber.InvalidEmail(email)));
                }

                var user = new TUser();
                await userStore.SetUserNameAsync(user, email, CancellationToken.None);
                await emailStore.SetEmailAsync(user, email, CancellationToken.None);
                var result = await userManager.CreateAsync(user, registration.Password);

                if (!result.Succeeded)
                {
                    return CreateValidationProblem(result);
                }

                await SendConfirmationEmailAsync(user, userManager, context, email);
                return TypedResults.Ok();
            });
        if (!exclude.Contains(IdentityApiEndpointPath.Login))
            routeGroup.MapPost($"/{IdentityApiEndpointPath.Login}",
                async Task<Results<Ok<AccessTokenResponse>, EmptyHttpResult, ProblemHttpResult>>
                ([FromBody] LoginRequest login, [FromServices] IServiceProvider sp) =>
                {
                    var signInManager = sp.GetRequiredService<SignInManager<TUser>>();
                    var tokenProvider = sp.GetRequiredService<TokenProviderService>();
                    var user = (await signInManager.UserManager.FindByEmailAsync(login.Email));
                   
                    if (user is null || !await signInManager.UserManager.CheckPasswordAsync(user, login.Password)) 
                    {
                        return TypedResults.Problem("Password is not correct!", statusCode: StatusCodes.Status401Unauthorized);
                    }

                    var accessToken = await tokenProvider.GenerateAccessAndRefreshTokensByUser(user as ApplicationUser ?? throw new InvalidOperationException());
                    
                    return TypedResults.Ok(accessToken);
                });
        if (!exclude.Contains(IdentityApiEndpointPath.Refresh))
            routeGroup.MapPost($"/{IdentityApiEndpointPath.Refresh}",
                async Task<Results<Ok<AccessTokenResponse>, UnauthorizedHttpResult, SignInHttpResult,
                        ChallengeHttpResult>>
                    ([FromBody] RefreshRequest refreshRequest, 
                        [FromServices] IServiceProvider sp,
                        [FromServices]TokenProviderService tokenProvider,
                        [FromServices]IdentityModuleDbContext dbContext) =>
                {
                    var refreshTokenUser = dbContext.RefreshTokens
                        .Include(x => x.User)
                        .Where(x =>
                            x.Token.Equals(refreshRequest.RefreshToken) 
                            && x.ExpireOnUtc > DateTime.UtcNow)
                        .Select(x => x.User)
                        .FirstOrDefault();
                    if (refreshTokenUser == null)
                        return TypedResults.Unauthorized();
                    
                    var accessToken = await tokenProvider.GenerateAccessAndRefreshTokensByUser(refreshTokenUser);
                    return TypedResults.Ok(accessToken);
                });
        if (!exclude.Contains(IdentityApiEndpointPath.ConfirmEmail))
            routeGroup.MapGet($"/{IdentityApiEndpointPath.ConfirmEmail}",
                    async Task<Results<ContentHttpResult, UnauthorizedHttpResult>>
                    ([FromQuery] string userId, [FromQuery] string code, [FromQuery] string? changedEmail,
                        [FromServices] IServiceProvider sp) =>
                    {
                        var userManager = sp.GetRequiredService<UserManager<TUser>>();
                        if (await userManager.FindByIdAsync(userId) is not { } user)
                        {
                            // We could respond with a 404 instead of a 401 like Identity UI, but that feels like unnecessary information.
                            return TypedResults.Unauthorized();
                        }

                        try
                        {
                            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
                        }
                        catch (FormatException)
                        {
                            return TypedResults.Unauthorized();
                        }

                        IdentityResult result;

                        if (string.IsNullOrEmpty(changedEmail))
                        {
                            result = await userManager.ConfirmEmailAsync(user, code);
                        }
                        else
                        {
                            // As with Identity UI, email and user name are one and the same. So when we update the email,
                            // we need to update the user name.
                            result = await userManager.ChangeEmailAsync(user, changedEmail, code);

                            if (result.Succeeded)
                            {
                                result = await userManager.SetUserNameAsync(user, changedEmail);
                            }
                        }

                        if (!result.Succeeded)
                        {
                            return TypedResults.Unauthorized();
                        }

                        return TypedResults.Text("Thank you for confirming your email.");
                    })
                .Add(endpointBuilder =>
                {
                    var finalPattern = ((RouteEndpointBuilder)endpointBuilder).RoutePattern.RawText;
                    confirmEmailEndpointName = $"{nameof(MapCustomIdentityApi)}-{finalPattern}";
                    endpointBuilder.Metadata.Add(new EndpointNameMetadata(confirmEmailEndpointName));
                });
        if (!exclude.Contains(IdentityApiEndpointPath.ResendConfirmationEmail))
            routeGroup.MapPost($"/{IdentityApiEndpointPath.ResendConfirmationEmail}", async Task<Ok>
            ([FromBody] ResendConfirmationEmailRequest resendRequest, HttpContext context,
                [FromServices] IServiceProvider sp) =>
            {
                var userManager = sp.GetRequiredService<UserManager<TUser>>();
                if (await userManager.FindByEmailAsync(resendRequest.Email) is not { } user)
                {
                    return TypedResults.Ok();
                }

                await SendConfirmationEmailAsync(user, userManager, context, resendRequest.Email);
                return TypedResults.Ok();
            });
        if (!exclude.Contains(IdentityApiEndpointPath.ForgotPassword))
            routeGroup.MapPost($"/{IdentityApiEndpointPath.ForgotPassword}", async Task<Results<Ok, ValidationProblem>>
                ([FromBody] ForgotPasswordRequest resetRequest, [FromServices] IServiceProvider sp) =>
            {
                var userManager = sp.GetRequiredService<UserManager<TUser>>();
                var user = await userManager.FindByEmailAsync(resetRequest.Email);

                if (user is not null && await userManager.IsEmailConfirmedAsync(user))
                {
                    var code = await userManager.GeneratePasswordResetTokenAsync(user);
                    code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

                    await emailSender.SendPasswordResetCodeAsync(user, resetRequest.Email,
                        HtmlEncoder.Default.Encode(code));
                }

                // Don't reveal that the user does not exist or is not confirmed, so don't return a 200 if we would have
                // returned a 400 for an invalid code given a valid user email.
                return TypedResults.Ok();
            });
        if (!exclude.Contains(IdentityApiEndpointPath.ResetPassword))
            routeGroup.MapPost($"/{IdentityApiEndpointPath.ResetPassword}", async Task<Results<Ok, ValidationProblem>>
                ([FromBody] ResetPasswordRequest resetRequest, [FromServices] IServiceProvider sp) =>
            {
                var userManager = sp.GetRequiredService<UserManager<TUser>>();

                var user = await userManager.FindByEmailAsync(resetRequest.Email);

                if (user is null || !(await userManager.IsEmailConfirmedAsync(user)))
                {
                    // Don't reveal that the user does not exist or is not confirmed, so don't return a 200 if we would have
                    // returned a 400 for an invalid code given a valid user email.
                    return CreateValidationProblem(IdentityResult.Failed(userManager.ErrorDescriber.InvalidToken()));
                }

                IdentityResult result;
                try
                {
                    var code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(resetRequest.ResetCode));
                    result = await userManager.ResetPasswordAsync(user, code, resetRequest.NewPassword);
                }
                catch (FormatException)
                {
                    result = IdentityResult.Failed(userManager.ErrorDescriber.InvalidToken());
                }

                if (!result.Succeeded)
                {
                    return CreateValidationProblem(result);
                }

                return TypedResults.Ok();
            });

        var accountGroup = routeGroup.MapGroup($"/{IdentityApiEndpointPath.Manage}").RequireAuthorization();
        if (!exclude.Contains(IdentityApiEndpointPath.TwoFa))
            accountGroup.MapPost($"/{IdentityApiEndpointPath.TwoFa}",
                async Task<Results<Ok<TwoFactorResponse>, ValidationProblem, NotFound>>
                (ClaimsPrincipal claimsPrincipal, [FromBody] TwoFactorRequest tfaRequest,
                    [FromServices] IServiceProvider sp) =>
                {
                    var signInManager = sp.GetRequiredService<SignInManager<TUser>>();
                    var userManager = signInManager.UserManager;
                    if (await userManager.GetUserAsync(claimsPrincipal) is not { } user)
                    {
                        return TypedResults.NotFound();
                    }

                    if (tfaRequest.Enable == true)
                    {
                        if (tfaRequest.ResetSharedKey)
                        {
                            return CreateValidationProblem("CannotResetSharedKeyAndEnable",
                                "Resetting the 2fa shared key must disable 2fa until a 2fa token based on the new shared key is validated.");
                        }

                        if (string.IsNullOrEmpty(tfaRequest.TwoFactorCode))
                        {
                            return CreateValidationProblem("RequiresTwoFactor",
                                "No 2fa token was provided by the request. A valid 2fa token is required to enable 2fa.");
                        }

                        if (!await userManager.VerifyTwoFactorTokenAsync(user,
                                userManager.Options.Tokens.AuthenticatorTokenProvider, tfaRequest.TwoFactorCode))
                        {
                            return CreateValidationProblem("InvalidTwoFactorCode",
                                "The 2fa token provided by the request was invalid. A valid 2fa token is required to enable 2fa.");
                        }

                        await userManager.SetTwoFactorEnabledAsync(user, true);
                    }
                    else if (tfaRequest.Enable == false || tfaRequest.ResetSharedKey)
                    {
                        await userManager.SetTwoFactorEnabledAsync(user, false);
                    }

                    if (tfaRequest.ResetSharedKey)
                    {
                        await userManager.ResetAuthenticatorKeyAsync(user);
                    }

                    string[]? recoveryCodes = null;
                    if (tfaRequest.ResetRecoveryCodes || (tfaRequest.Enable == true &&
                                                          await userManager.CountRecoveryCodesAsync(user) == 0))
                    {
                        var recoveryCodesEnumerable =
                            await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
                        recoveryCodes = recoveryCodesEnumerable?.ToArray();
                    }

                    if (tfaRequest.ForgetMachine)
                    {
                        await signInManager.ForgetTwoFactorClientAsync();
                    }

                    var key = await userManager.GetAuthenticatorKeyAsync(user);
                    if (string.IsNullOrEmpty(key))
                    {
                        await userManager.ResetAuthenticatorKeyAsync(user);
                        key = await userManager.GetAuthenticatorKeyAsync(user);

                        if (string.IsNullOrEmpty(key))
                        {
                            throw new NotSupportedException(
                                "The user manager must produce an authenticator key after reset.");
                        }
                    }

                    return TypedResults.Ok(new TwoFactorResponse
                    {
                        SharedKey = key,
                        RecoveryCodes = recoveryCodes,
                        RecoveryCodesLeft = recoveryCodes?.Length ?? await userManager.CountRecoveryCodesAsync(user),
                        IsTwoFactorEnabled = await userManager.GetTwoFactorEnabledAsync(user),
                        IsMachineRemembered = await signInManager.IsTwoFactorClientRememberedAsync(user),
                    });
                });
        if (!exclude.Contains(IdentityApiEndpointPath.Info))
            accountGroup.MapGet($"/{IdentityApiEndpointPath.Info}",
                async Task<Results<Ok<InfoResponse>, ValidationProblem, NotFound>>
                    (ClaimsPrincipal claimsPrincipal, [FromServices] IServiceProvider sp) =>
                {
                    var userManager = sp.GetRequiredService<UserManager<TUser>>();
                    if (await userManager.GetUserAsync(claimsPrincipal) is not { } user)
                    {
                        return TypedResults.NotFound();
                    }

                    return TypedResults.Ok(await CreateInfoResponseAsync(user, userManager));
                });
        if (!exclude.Contains(IdentityApiEndpointPath.Info))
            accountGroup.MapPost($"/{IdentityApiEndpointPath.Info}",
                async Task<Results<Ok<InfoResponse>, ValidationProblem, NotFound>>
                (ClaimsPrincipal claimsPrincipal, [FromBody] InfoRequest infoRequest, HttpContext context,
                    [FromServices] IServiceProvider sp) =>
                {
                    var userManager = sp.GetRequiredService<UserManager<TUser>>();
                    if (await userManager.GetUserAsync(claimsPrincipal) is not { } user)
                    {
                        return TypedResults.NotFound();
                    }

                    if (!string.IsNullOrEmpty(infoRequest.NewEmail) &&
                        !_emailAddressAttribute.IsValid(infoRequest.NewEmail))
                    {
                        return CreateValidationProblem(
                            IdentityResult.Failed(userManager.ErrorDescriber.InvalidEmail(infoRequest.NewEmail)));
                    }

                    if (!string.IsNullOrEmpty(infoRequest.NewPassword))
                    {
                        if (string.IsNullOrEmpty(infoRequest.OldPassword))
                        {
                            return CreateValidationProblem("OldPasswordRequired",
                                "The old password is required to set a new password. If the old password is forgotten, use /resetPassword.");
                        }

                        var changePasswordResult =
                            await userManager.ChangePasswordAsync(user, infoRequest.OldPassword,
                                infoRequest.NewPassword);
                        if (!changePasswordResult.Succeeded)
                        {
                            return CreateValidationProblem(changePasswordResult);
                        }
                    }

                    if (!string.IsNullOrEmpty(infoRequest.NewEmail))
                    {
                        var email = await userManager.GetEmailAsync(user);

                        if (email != infoRequest.NewEmail)
                        {
                            await SendConfirmationEmailAsync(user, userManager, context, infoRequest.NewEmail,
                                isChange: true);
                        }
                    }

                    return TypedResults.Ok(await CreateInfoResponseAsync(user, userManager));
                });

        async Task SendConfirmationEmailAsync(TUser user, UserManager<TUser> userManager, HttpContext context,
            string email, bool isChange = false)
        {
            if (confirmEmailEndpointName is null)
            {
                throw new NotSupportedException("No email confirmation endpoint was registered!");
            }

            var code = isChange
                ? await userManager.GenerateChangeEmailTokenAsync(user, email)
                : await userManager.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            var userId = await userManager.GetUserIdAsync(user);
            var routeValues = new RouteValueDictionary()
            {
                ["userId"] = userId,
                ["code"] = code,
            };

            if (isChange)
            {
                // This is validated by the /confirmEmail endpoint on change.
                routeValues.Add("changedEmail", email);
            }

            var confirmEmailUrl = linkGenerator.GetUriByName(context, confirmEmailEndpointName, routeValues)
                                  ?? throw new NotSupportedException(
                                      $"Could not find endpoint named '{confirmEmailEndpointName}'.");

            await emailSender.SendConfirmationLinkAsync(user, email, HtmlEncoder.Default.Encode(confirmEmailUrl));
        }

        return new IdentityEndpointsConventionBuilder(routeGroup);
    }

    private static ValidationProblem CreateValidationProblem(string errorCode, string errorDescription) =>
        TypedResults.ValidationProblem(new Dictionary<string, string[]>
        {
            { errorCode, [errorDescription] }
        });

    private static ValidationProblem CreateValidationProblem(IdentityResult result)
    {
        // We expect a single error code and description in the normal case.
        // This could be golfed with GroupBy and ToDictionary, but perf! :P
        Debug.Assert(!result.Succeeded);
        var errorDictionary = new Dictionary<string, string[]>(1);

        foreach (var error in result.Errors)
        {
            string[] newDescriptions;

            if (errorDictionary.TryGetValue(error.Code, out var descriptions))
            {
                newDescriptions = new string[descriptions.Length + 1];
                Array.Copy(descriptions, newDescriptions, descriptions.Length);
                newDescriptions[descriptions.Length] = error.Description;
            }
            else
            {
                newDescriptions = [error.Description];
            }

            errorDictionary[error.Code] = newDescriptions;
        }

        return TypedResults.ValidationProblem(errorDictionary);
    }

    private static async Task<InfoResponse> CreateInfoResponseAsync<TUser>(TUser user, UserManager<TUser> userManager)
        where TUser : class
    {
        return new()
        {
            Email = await userManager.GetEmailAsync(user) ??
                    throw new NotSupportedException("Users must have an email."),
            IsEmailConfirmed = await userManager.IsEmailConfirmedAsync(user),
        };
    }

    // Wrap RouteGroupBuilder with a non-public type to avoid a potential future behavioral breaking change.
    private sealed class IdentityEndpointsConventionBuilder(RouteGroupBuilder inner) : IEndpointConventionBuilder
    {
        private IEndpointConventionBuilder InnerAsConventionBuilder => inner;

        public void Add(Action<EndpointBuilder> convention) => InnerAsConventionBuilder.Add(convention);

        public void Finally(Action<EndpointBuilder> finallyConvention) =>
            InnerAsConventionBuilder.Finally(finallyConvention);
    }

    [AttributeUsage(AttributeTargets.Parameter)]
    private sealed class FromBodyAttribute : Attribute, IFromBodyMetadata
    {
    }

    [AttributeUsage(AttributeTargets.Parameter)]
    private sealed class FromServicesAttribute : Attribute, IFromServiceMetadata
    {
    }

    [AttributeUsage(AttributeTargets.Parameter)]
    private sealed class FromQueryAttribute : Attribute, IFromQueryMetadata
    {
        public string? Name => null;
    }
}