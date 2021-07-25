using System;
using System.Collections.Generic;

namespace Auth.Server.Models
{
    public class IdentityViewModel
    {
        public Identity Identity { get; set; }
        
        public IList<AuthProvider> AuthProviders { get; set; }
        
        public IList<Role> Roles { get; set; }
    }
}