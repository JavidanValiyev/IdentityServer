using System.Text;
using IdentityServer.Configurations;
using IdentityServer.Data.Models;
using IdentityServer.Endpoints;
using IdentityServer.Services;
using MassTransit;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace IdentityServer.Data;

public static class IdentityServiceConfigurations
{
    public static IServiceCollection AddIdentityServer(this IServiceCollection services,ConfigurationManager configurationManager)
    {
        var connString = configurationManager["IdentityModule:Data:ConnectionStrings"];
        var schema = configurationManager["IdentityModule:Data:Schema"];
        services.Configure<IdentityModuleConfiguration>(configurationManager.GetSection("IdentityModule"));
        services.AddDbContext<IdentityModuleDbContext>(options =>
            options.UseSqlServer(connString,
                x=>x.MigrationsHistoryTable("__IdentityModuleMigrationsHistoryTable",schema)));
        services.AddIdentityCore<ApplicationUser>(options =>
            {
                options.User.RequireUniqueEmail = true;
                options.SignIn.RequireConfirmedEmail = false;
            })
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<IdentityModuleDbContext>()
            .AddApiEndpoints();
        services.Configure<IdentityOptions>(options =>
        {
            options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
            options.Lockout.MaxFailedAccessAttempts = 5;
            options.Lockout.AllowedForNewUsers = true;
        });
        string secretKey = configurationManager.GetValue<string>("IdentityModule:Jwt:SecretKey") ??  throw new ArgumentNullException(nameof(services));
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(options =>
        {
            options.TokenValidationParameters.ValidIssuer = configurationManager.GetValue<string>("IdentityModule:Jwt:Issuer");
            options.TokenValidationParameters.ValidAudience = configurationManager.GetValue<string>("IdentityModule:Jwt:Audience");
            options.TokenValidationParameters.IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            options.TokenValidationParameters.ValidAlgorithms = [SecurityAlgorithms.HmacSha256];
        });
        services.AddAuthorization();
        services.AddHttpContextAccessor();

        services.AddScoped<DatabaseInitialiser>();
        services.AddScoped<TokenProviderService>();
        return services;
    }

    public static IApplicationBuilder UseIdentityServer(this WebApplication app)
    {
     
        app.MapGroup($"/{IdentityApiEndpointPath.Group}")
            .MapCustomIdentityApi<ApplicationUser>(IdentityApiEndpointPath.Register);
        return app;
    }
}