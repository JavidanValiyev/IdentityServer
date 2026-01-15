using IdentityServer.Data.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace IdentityServer.Data.ModelConfigurations;

public class RefreshTokenEntityConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.HasKey(r => r.Id);
        builder.HasOne(x => x.User)
            .WithMany()
            .HasForeignKey(r => r.UserId);
        builder.Property(r => r.Token).IsRequired();
        builder.Property(r => r.UserId).IsRequired();
        builder.Property(r => r.CreatedOnUtc).IsRequired();
        builder.Property(r => r.ExpireOnUtc).IsRequired();
    }
}