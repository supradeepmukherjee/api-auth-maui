namespace api_maui.DTOs
{
    public class AuthDtos
    {
        public record RegisterDto(string? Email, string? PhoneNumber, string Password, string? DisplayName);
        public record LoginDto(string Identifier, string Password);
        public record TokenResponseDto(string AccessToken, string RefreshToken, int ExpiresInSeconds);
        public record RefreshRequest(string RefreshToken);
        public record ExternalLoginRequest(string Provider, string IdToken);
    }
}
