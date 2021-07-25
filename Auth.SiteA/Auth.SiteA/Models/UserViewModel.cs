using System.Security.Cryptography;

namespace Auth.SiteA.Models
{
    public class UserViewModel
    {
        public User User { get; set; }
        public string Claim { get; set; }
        

        public string SetPasswordUrl { get; set; }

        
        public string LoginUrl { get; set; }

        public string LogoutUrl { get; set; }
    }
}