using System;

namespace Auth.Server.Models
{
    public class Identity
    {
        public int Id { get; set; }
        
        public Guid Token { get; set; }
    }
}