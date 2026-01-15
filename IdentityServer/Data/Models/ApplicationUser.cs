using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Data.Models;

public class ApplicationUser : IdentityUser
{
    public Guid? TenantId { get; set; }
}