namespace Auth.Server.Models
{
    public class SetPasswordViewModel
    {
        public int Id { get; set; }
        
        public string Password { get; set; }
        
        public string RedirectUrl { get; set; }
    }
}