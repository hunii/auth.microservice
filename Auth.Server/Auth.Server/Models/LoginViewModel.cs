namespace Auth.Server.Models
{
    public class LoginViewModel
    {
        // Enum
        public bool IsFacebookAuth { get; set; }
        
        public string Email { get; set; }
        
        public string Password { get; set; }
        
        public string RedirectUrl { get; set; }
    }
}