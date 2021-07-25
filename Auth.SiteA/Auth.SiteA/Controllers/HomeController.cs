using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Auth.SiteA.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Auth.SiteA.Controllers
{
    public class HomeController : Controller
    {
        private static string Secret= "brandcrowdsecret";
        private static string AuthServerUrl = "https://localhost:5101";
        private static string AuthServerIssuer= "https://localhost:5101"; // Auth.Server URL
        private static string SelfSiteUrl= "https://localhost:5201"; // Auth.Site URL
        private static string AuthSiteAudience= "https://localhost:5201"; // Auth.Site URL
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly IHttpClientFactory _httpClientFactory;

        private static IList<User> Users = new List<User>
        {
            new User { AuthId = 1, Id = 1313, Name = "James", Email = "james@designcrowd.com"},
            new User { AuthId = 2, Id = 2422, Name = "Joe", Email = "joe@designcrowd.com"},
        };
        
        public HomeController(IHttpContextAccessor contextAccessor, IHttpClientFactory httpClientFactory)
        {
            _contextAccessor = contextAccessor;
            _httpClientFactory = httpClientFactory;
        }

        public IActionResult Index()
        {
            var userPrincipal = _contextAccessor.HttpContext.User;
            User user = null;
            var userIdClaim = userPrincipal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier);
            if (userIdClaim != null)
            {
                user = Users.FirstOrDefault(x => x.Id.ToString() == userIdClaim.Value);
            }

            var claimJson = JsonConvert.SerializeObject(new {claims = userPrincipal.Claims.Select(x => new
            {
                x.Type, x.Value
            })}, Formatting.Indented);

            var requestSetPasswordToken = GenerateToken($"{SelfSiteUrl}/LoginSuccess", user?.AuthId);
            var requestLogoutToken = GenerateToken(SelfSiteUrl, null);
            var loginToken = GenerateToken($"{SelfSiteUrl}/LoginSuccess", null);
            
            return View("Index", new UserViewModel()
            {
                User = user,
                Claim = claimJson,
                LoginUrl = $"{AuthServerUrl}/ç?token={loginToken}",
                LogoutUrl = $"{AuthServerUrl}/logout?token={requestLogoutToken}",
                SetPasswordUrl = user != null ? $"{AuthServerUrl}/setpassword?token={requestSetPasswordToken}" : "",
            });
        }
        
        [HttpPost("Register", Name = "register")]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!string.IsNullOrEmpty(model.Email))
            {
                using (var client = _httpClientFactory.CreateClient("client"))
                {
                    var urlCheckEmailExist = $"https://localhost:5101/emailexist?email={model.Email}";
                    var emailExistResponse = await client.GetAsync(urlCheckEmailExist);
                    var json = await emailExistResponse.Content.ReadAsStringAsync();
                    var obj = JObject.Parse(json);
                    var exist = obj["exist"].ToObject<bool>();

                    if (exist)
                    {
                        var requestLoginToken = GenerateToken($"{SelfSiteUrl}/LoginSuccess", null);
                        return Redirect($"{AuthServerUrl}/challenge?token={requestLoginToken}");
                    }

                    var url = $"https://localhost:5101/register?email={model.Email}";
                    var response = await client.PostAsync(url, new StringContent(""));
                    if (response.IsSuccessStatusCode)
                    {
                        json = await response.Content.ReadAsStringAsync();
                        obj = JObject.Parse(json);
                        var authId = obj["id"].ToString();
                        var newUser = new User
                        {
                            Id = Users.Max(x => x.Id) + 1,
                            AuthId = int.Parse(authId),
                            Email = model.Email
                        };
                        Users.Add(newUser);

                        await LoginAsync(newUser.Id, !string.IsNullOrEmpty(newUser.Name) ? newUser.Name : newUser.Email, new List<Claim>(), false);
                    }
                }
            }
            
            return RedirectToAction("Index");
        }
        
        [HttpGet("LoginSuccess")]
        public async Task<IActionResult> LoginSuccess(string token)
        {
            var authClaimPrincipal = GetValidatedClaims(token);
            if (authClaimPrincipal != null)
            {
                var nameIdentifier = authClaimPrincipal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier);
                var permissionClaims = authClaimPrincipal.Claims.Where(x => x.Type == "Permission").ToList();

                var user = Users.FirstOrDefault(x => x.AuthId.ToString() == nameIdentifier.Value);

                await LoginAsync(user.Id, user.Name, permissionClaims,true);
                
            }
            
            return RedirectToAction("Index");
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel {RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier});
        }

        private async Task LoginAsync(int userid, string name, IList<Claim> extraClaims, bool hardLogin)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, userid.ToString()),
                new Claim(ClaimTypes.Name, name),
            };
            if (hardLogin)
                claims.Add(new Claim("Permission", "HardLogin"));
            claims.AddRange(extraClaims);
                
            var claimsIdentity = new ClaimsIdentity(
                claims, CookieAuthenticationDefaults.AuthenticationScheme);
                
            await _contextAccessor.HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme, 
                new ClaimsPrincipal(claimsIdentity));
        }
        
        private ClaimsPrincipal GetValidatedClaims(string token)
        {
            var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Secret));

            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                return tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = AuthServerIssuer,
                    ValidAudience = AuthSiteAudience,
                    IssuerSigningKey = mySecurityKey
                }, out SecurityToken validatedToken);
            }
            catch {}
            return null;
        }
        
        public string GenerateToken(string redirectUrl, int? id)
        {
            var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Secret));
            
            var claims = new List<Claim>
            {
                new Claim("RedirectUrl", redirectUrl),
            };

            if (id.HasValue)
            {
                claims.Add(new Claim(ClaimTypes.NameIdentifier, id.Value.ToString()));
            }
            
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(2),
                Issuer = AuthSiteAudience,
                Audience = AuthServerIssuer,
                SigningCredentials = new SigningCredentials(mySecurityKey, SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}