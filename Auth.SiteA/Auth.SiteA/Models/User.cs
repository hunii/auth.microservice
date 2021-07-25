using System.Security.Cryptography;

namespace Auth.SiteA.Models
{
    public class User
    {
        public int Id { get; set; }
        
        public int AuthId { get; set; }

        public string Name { get; set; }
        
        public string Email { get; set; }
    }
}