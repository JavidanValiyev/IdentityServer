using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using IdentityServer.Configurations;
using IdentityServer.Data;
using IdentityServer.Data.Models;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer.Services;

public class TokenProviderService(UserManager<ApplicationUser> userManager,
    IOptions<IdentityModuleConfiguration> options,
    IdentityModuleDbContext dbContext)
{

    public async Task<AccessTokenResponse> GenerateAccessAndRefreshTokensByUser(ApplicationUser user)
    {
        var roles = await userManager.GetRolesAsync(user);
        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.Value.Jwt.SecretKey));
        var credentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
        
        List<Claim> claims =
        [
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email!),
            new(JwtRegisteredClaimNames.FamilyName,user.TenantId.ToString()),

        ];
        claims.AddRange(roles.Select(x=>new Claim(ClaimTypes.Role,x)).ToList());
        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(options.Value.Jwt.AccessTokenExpireInMinute),
            SigningCredentials = credentials,
            Issuer = options.Value.Jwt.Issuer,
            Audience = options.Value.Jwt.Audience,
        };
        var tokenHandler = new JsonWebTokenHandler();
        string accessToken = tokenHandler.CreateToken(tokenDescriptor);
        string refreshToken = await GenerateRefreshToken();
       
        await dbContext.RefreshTokens.Where(x=>x.UserId == user.Id)
            .ExecuteDeleteAsync();
        
        await dbContext.RefreshTokens.AddAsync(new RefreshToken()
        {
            Token = refreshToken,
            CreatedOnUtc = DateTime.UtcNow,
            UserId = user.Id,
            ExpireOnUtc = DateTime.UtcNow.AddMinutes(options.Value.Jwt.RefreshTokenExpireInMinute),
        });
        await dbContext.SaveChangesAsync();
        return new AccessTokenResponse()
        {
            AccessToken = accessToken,
            ExpiresIn = options.Value.Jwt.AccessTokenExpireInMinute,
            RefreshToken = refreshToken
        };
    }
    
    private Task<string> GenerateRefreshToken()
    {
        return Task.FromResult(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
    }
}