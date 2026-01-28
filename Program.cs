using api_maui.Data;
using api_maui.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Diagnostics;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;

builder.Services.AddDbContext<AuthDbContext>(opt =>
    opt.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));

var jwtKey = configuration["Jwt:Key"] ?? throw new InvalidOperationException("Jwt:Key missing");
var jwtIssuer = configuration["Jwt:Issuer"] ?? "AuthDemo";
var keyBytes = Encoding.UTF8.GetBytes(jwtKey);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = true;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = jwtIssuer,
        ValidateAudience = true,
        ValidAudience = jwtIssuer,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromSeconds(30)
    };
})
;

builder.Services.AddAuthorization();
builder.Services.AddScoped<IAuthService, AuthService>();

var app = builder.Build();

app.Use(async (context, next) =>
{
    Console.WriteLine($" {context.Request.Method} {context.Request.Scheme}://{context.Request.Host}{context.Request.Path}");
    await next();
});


app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/register", async (api_maui.DTOs.AuthDtos.RegisterDto dto, IAuthService auth) =>
{
    var user = await auth.RegisterAsync(dto);
    return user is null ? Results.BadRequest(new { error = "Unable to register" }) : Results.Ok(new { user.Id, user.Email, user.PhoneNumber, user.DisplayName });
});

app.MapPost("/login", async (api_maui.DTOs.AuthDtos.LoginDto dto, IAuthService auth) =>
{
    var tokens = await auth.LoginAsync(dto);
    return tokens is null ? Results.Unauthorized() : Results.Ok(tokens);
});

app.MapPost("/refresh", async (api_maui.DTOs.AuthDtos.RefreshRequest req, IAuthService auth) =>
{
    var res = await auth.RefreshAsync(req.RefreshToken);
    return res is null ? Results.Unauthorized() : Results.Ok(res);
});

app.MapPost("/revoke", async (api_maui.DTOs.AuthDtos.RefreshRequest req, IAuthService auth) =>
{
    var ok = await auth.RevokeRefreshTokenAsync(req.RefreshToken);
    return ok ? Results.Ok() : Results.BadRequest();
});

app.MapPost("/external-login", async (api_maui.DTOs.AuthDtos.ExternalLoginRequest req, IAuthService auth) =>
{
    var tokens = await auth.ExternalLoginAsync(req);
    return tokens is null ? Results.Unauthorized() : Results.Ok(tokens);
});

app.MapGet("/me", [Microsoft.AspNetCore.Authorization.Authorize] (ClaimsPrincipal user) =>
{
    return Results.Ok(new
    {
        Id = user.FindFirstValue(ClaimTypes.NameIdentifier),
        Email = user.FindFirstValue(ClaimTypes.Email),
        Name = user.FindFirstValue(ClaimTypes.Name),
        Phone = user.FindFirst("phone")?.Value,
        Roles = user.FindAll(ClaimTypes.Role).Select(r => r.Value),
        Provider = user.FindFirst("provider")?.Value
    });
});

app.Run();