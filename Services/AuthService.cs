using api_maui.Data;
using api_maui.DTOs;
using api_maui.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using static api_maui.DTOs.AuthDtos;

namespace api_maui.Services
{
    public class AuthService : IAuthService
    {
        private readonly AuthDbContext _db;
        private readonly IConfiguration _config;

        public AuthService(AuthDbContext db, IConfiguration config)
        {
            _db = db;
            _config = config;
        }

        public async Task<User?> RegisterAsync(RegisterDto dto)
        {
            if (string.IsNullOrWhiteSpace(dto.Password)) return null;
            if (string.IsNullOrWhiteSpace(dto.Email) && string.IsNullOrWhiteSpace(dto.PhoneNumber)) return null;

            var exists = await _db.Users.AnyAsync(u =>
                (dto.Email != null && u.Email == dto.Email) ||
                (dto.PhoneNumber != null && u.PhoneNumber == dto.PhoneNumber)
            );
            if (exists) return null;

            var user = new User
            {
                Email = dto.Email,
                PhoneNumber = dto.PhoneNumber,
                DisplayName = dto.DisplayName,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.Password)
            };

            _db.Users.Add(user);
            await _db.SaveChangesAsync();
            return user;
        }

        public async Task<TokenResponseDto?> LoginAsync(LoginDto dto)
        {
            var user = await _db.Users
                .Include(u => u.RefreshTokens)
                .FirstOrDefaultAsync(u => u.Email == dto.Identifier || u.PhoneNumber == dto.Identifier);

            if (user == null) return null;
            if (!BCrypt.Net.BCrypt.Verify(dto.Password, user.PasswordHash)) return null;

            return await CreateTokensForUserAsync(user);
        }

        public async Task<TokenResponseDto?> RefreshAsync(string refreshToken)
        {
            var token = await _db.RefreshTokens.Include(t => t.User)
                .FirstOrDefaultAsync(t => t.Token == refreshToken && !t.Revoked);

            if (token == null) return null;
            if (token.ExpiresAt < DateTime.UtcNow) return null;

            token.Revoked = true;
            await _db.SaveChangesAsync();

            return await CreateTokensForUserAsync(token.User);
        }

        public async Task<bool> RevokeRefreshTokenAsync(string refreshToken)
        {
            var token = await _db.RefreshTokens.FirstOrDefaultAsync(t => t.Token == refreshToken);
            if (token == null) return false;
            token.Revoked = true;
            await _db.SaveChangesAsync();
            return true;
        }

        public async Task<TokenResponseDto?> ExternalLoginAsync(ExternalLoginRequest req)
        {
            if (req.Provider?.ToLower() != "google") return null;

            var googleClientId = _config["Authentication:Google:ClientId"];
            if (string.IsNullOrWhiteSpace(googleClientId)) return null;

            using var http = new HttpClient();
            var tokenInfoUrl = $"https://oauth2.googleapis.com/tokeninfo?id_token={req.IdToken}";
            var r = await http.GetAsync(tokenInfoUrl);
            if (!r.IsSuccessStatusCode) return null;

            var json = await r.Content.ReadFromJsonAsync<JsonElement>();
            if (!json.TryGetProperty("aud", out var aud) || aud.GetString() != googleClientId) return null;

            var email = json.TryGetProperty("email", out var e) ? e.GetString() : null;
            var name = json.TryGetProperty("name", out var n) ? n.GetString() : null;
            var sub = json.TryGetProperty("sub", out var s) ? s.GetString() : null;

            if (email == null) return null;

            var user = await _db.Users.Include(u => u.RefreshTokens).FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
            {
                user = new User
                {
                    Email = email,
                    DisplayName = name ?? email,
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword(Guid.NewGuid().ToString()) // random password
                };
                _db.Users.Add(user);
                await _db.SaveChangesAsync();
            }

            return await CreateTokensForUserAsync(user);
        }

        private async Task<TokenResponseDto> CreateTokensForUserAsync(User user)
        {
            var jwt = CreateJwtForUser(user);
            var refresh = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                ExpiresAt = DateTime.UtcNow.AddDays(30),
                UserId = user.Id
            };
            _db.RefreshTokens.Add(refresh);
            await _db.SaveChangesAsync();

            return new TokenResponseDto(jwt.TokenString, refresh.Token, (int)jwt.ExpiresInSeconds);
        }

        private (string TokenString, double ExpiresInSeconds) CreateJwtForUser(User user)
        {
            var jwtKey = _config["Jwt:Key"] ?? throw new InvalidOperationException("Missing Jwt:Key");
            var jwtIssuer = _config["Jwt:Issuer"] ?? "AuthDemo";
            var jwtExpireSeconds = int.Parse(_config["Jwt:ExpireSeconds"] ?? "900");

            var claims = new List<Claim>
{
    new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
    new Claim(ClaimTypes.Name, user.DisplayName ?? user.Email ?? ""),
    new Claim(ClaimTypes.Role, user.Role)
};

            if (!string.IsNullOrEmpty(user.Email))
                claims.Add(new Claim(ClaimTypes.Email, user.Email));

            if (!string.IsNullOrEmpty(user.PhoneNumber))
                claims.Add(new Claim("phone", user.PhoneNumber));

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var now = DateTime.UtcNow;
            var expires = now.AddSeconds(jwtExpireSeconds);

            var jwt = new JwtSecurityToken(
                issuer: jwtIssuer,
                audience: jwtIssuer,
                claims: claims,
                notBefore: now,
                expires: expires,
                signingCredentials: cred
            );

            var token = new JwtSecurityTokenHandler().WriteToken(jwt);
            return (token, (expires - now).TotalSeconds);
        }
    }
}
