using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Auth.Server.Models;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Server.Services
{
    public class AuthService
    {
        public static string Secret= "brandcrowdsecret";
        public static string AuthServerIssuer= "https://localhost:5101"; // Auth.Server URL
        public static string AuthSiteAudience= "https://localhost:5201"; // Auth.Site URL
        
        public static IList<Identity> IdentitiesDB = new List<Identity>
        {
            new Identity { Id = 1, Token = Guid.NewGuid() },
            new Identity { Id = 2, Token = Guid.NewGuid() },
        };
        
        public static IList<AuthProvider> AuthProvidersDB = new List<AuthProvider>
        {
            new AuthProvider{ Type = AuthProviderType.Basic, IdentityId = 1, Email = "james@designcrowd.com", Password = "password1"},
            new AuthProvider{ Type = AuthProviderType.Facebook, IdentityId = 1, Email = "james@facebook.com", Password = "password1"},
            new AuthProvider{ Type = AuthProviderType.Basic, IdentityId = 2, Email = "joe@designcrowd.com", Password = "password1"},
        };
        
        public static IList<Role> RolesDB = new List<Role>
        {
            new Role { AuthId = 1, Name = "Developer"},
            new Role { AuthId = 1, Name = "Admin"},
            new Role { AuthId = 2, Name = "Admin"},
        };


        public IList<Identity> GetAllIdentities()
        {
            return IdentitiesDB;
        }
        
        public IList<AuthProvider> GetAllAuthProvidersDB()
        {
            return AuthProvidersDB;
        } 
        
        public IList<Role> GetAllRoles()
        {
            return RolesDB;
        } 
        
        public AuthProvider GetAuthProvider(AuthProviderType authtype, string email, string password)
        {
            return AuthProvidersDB.SingleOrDefault(x => x.Type == authtype && x.Email == email && x.Password == password);
        }
        
        public string GenerateToken(int id, IList<Role> roles)
        {
            var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Secret));
            
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, id.ToString())
            };
            
            claims.AddRange(roles.Select(x => new Claim("Permission", x.Name)));
            
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(1),
                Issuer = AuthServerIssuer,
                Audience = AuthSiteAudience,
                SigningCredentials = new SigningCredentials(mySecurityKey, SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}