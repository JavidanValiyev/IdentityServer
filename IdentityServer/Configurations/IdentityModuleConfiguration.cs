namespace IdentityServer.Configurations;

public record IdentityModuleConfiguration
{
    public required Jwt Jwt { get; set; }
    public required IdentityModuleDataConfiguration Data { get; set; }
    public required RabbitMqConfigs RabbitMq { get; set; }
}

public record RabbitMqConfigs
{
    public required string Server { get; set; }
    public required string Port { get; set; }
    public required string User { get; set; }
    public required string Password { get; set; }
}
public record Jwt
{
    public required string Issuer { get; set; }
    public required string Audience { get; set; }
    public int AccessTokenExpireInMinute { get; set; }
    public int RefreshTokenExpireInMinute { get; set; } 
    public required string SecretKey { get; set; }
}

public record IdentityModuleDataConfiguration
{
    public required string ConnectionStrings { get; set; }
    public required string Schema { get; set; }
}