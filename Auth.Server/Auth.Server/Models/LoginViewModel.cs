using System.Collections.Generic;

namespace Auth.Server.Models
{
    public class LoginViewModel
    {
        // Enum
        public bool IsFacebookAuth { get; set; }
        
        public string Email { get; set; }
        
        public string Password { get; set; }
        
        public string RedirectUrl { get; set; }
        
        public IList<LoggedInUserSessionViewModel> LoggedInUserSessionViewModels { get; set; }
    }
    
    public class LoggedInUserSessionViewModel
    {
        public string Email { get; set; }
        public string AuthType { get; set; }
    }
}