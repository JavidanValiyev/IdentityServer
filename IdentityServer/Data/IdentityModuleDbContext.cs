using System.Reflection;
using IdentityServer.Configurations;
using IdentityServer.Data.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace IdentityServer.Data;

public class IdentityModuleDbContext(
    DbContextOptions<IdentityModuleDbContext> options,
    IOptions<IdentityModuleConfiguration> conf)
    : IdentityDbContext<ApplicationUser>(options)
{
    private readonly string _schema = conf.Value.Data.Schema;


    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfigurationsFromAssembly(
            Assembly.GetExecutingAssembly());
        modelBuilder.HasDefaultSchema(_schema);
        base.OnModelCreating(modelBuilder);
    }
    public DbSet<RefreshToken> RefreshTokens { get; set; }
}