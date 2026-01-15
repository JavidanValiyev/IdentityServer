using IdentityServer.Data;
using IdentityServer.Infrastructure;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// builder.Services.AddExceptionHandling();
builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
builder.Services.AddProblemDetails();
builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddIdentityServer(builder.Configuration);
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApi();
var app = builder.Build();

app.Map("/", () => $"Api {app.Environment.EnvironmentName} API!");
// Configure the HTTP request pipeline.

// app.UseErrorHandling();
if (app.Environment.IsDevelopment())
{
    await app.InitialiseDatabaseAsync();
    app.MapOpenApi();
    app.MapScalarApiReference("api");
}
app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.UseIdentityServer();
app.MapControllers();
app.Run();