namespace api_maui.Models
{
    public class User
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string? Email { get; set; }    
        public string? PhoneNumber { get; set; }
        public string PasswordHash { get; set; }
        public string? DisplayName { get; set; }
        public string Role { get; set; } = "User";

        public List<RefreshToken> RefreshTokens { get; set; } = new();
    }
}
