namespace IdentityServer.Data.Models;

public class RefreshToken 
{
    public RefreshToken()
    {
        
    }
    public int Id { get; set; }
    public string Token { get; set; }
    public string UserId { get; set; }
    public DateTime ExpireOnUtc { get; set; }
    public DateTime CreatedOnUtc { get; set; }
    public ApplicationUser? User { get; set; }
}