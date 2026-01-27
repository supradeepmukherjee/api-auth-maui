using api_maui.Models;
using static api_maui.DTOs.AuthDtos;

namespace api_maui.Services
{
    public interface IAuthService
    {
        Task<User?> RegisterAsync(RegisterDto dto);
        Task<TokenResponseDto?> LoginAsync(LoginDto dto);
        Task<TokenResponseDto?> RefreshAsync(string refreshToken);
        Task<bool> RevokeRefreshTokenAsync(string refreshToken);
        Task<TokenResponseDto?> ExternalLoginAsync(ExternalLoginRequest req);
    }
}
