namespace Auth.Server.Models
{
    public class AuthProvider
    {
        public AuthProviderType Type { get; set; }
        
        public int IdentityId { get; set; }
        
        public string Email { get; set; }
        
        public string Password { get; set; }
    }

    public enum AuthProviderType
    {
        Basic,
        Facebook,
    }
}