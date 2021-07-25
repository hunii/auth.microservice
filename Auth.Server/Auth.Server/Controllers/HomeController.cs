using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Auth.Server.Models;
using Auth.Server.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Server.Controllers
{
    public class HomeController : Controller
    {
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly AuthService _authService;

        public HomeController(IHttpContextAccessor contextAccessor, AuthService authService)
        {
            _contextAccessor = contextAccessor;
            _authService = authService;
        }
        
        [HttpGet("≈")]
        public IActionResult Challenge(string token)
        {
            var claimsPrincipal = GetValidatedClaims(token);
            if (claimsPrincipal == null)
            {
                return BadRequest();
            }

            var redirectUrlClaim = claimsPrincipal.Claims.FirstOrDefault(x => x.Type == "RedirectUrl");
            
            return RedirectToAction("Login", new { redirectUrl = redirectUrlClaim.Value, token = token });
        }
        
        [HttpGet()]
        public IActionResult Index()
        {
            return RedirectToAction("Login");
        }
        
        [HttpGet("Login")]
        public IActionResult Login(string redirectUrl, string token)
        {
            ViewBag.RedirectUrl = redirectUrl;

            var loggedInSessions = _contextAccessor.HttpContext.Request.Cookies.Where(x => x.Key.StartsWith("session-"))
                .Select(x => GetValidatedOwnClaims(x.Value)).ToList();

            var vm = new LoginViewModel()
            {
                LoggedInUserSessionViewModels = loggedInSessions.Select(x =>
                {
                    var authTypeClaim = x.Claims.First(x => x.Type == "AuthType").Value;
                    return new LoggedInUserSessionViewModel
                    {
                        Email = x.Claims.First(x => x.Type == ClaimTypes.Email).Value,
                        AuthType = authTypeClaim
                    };
                }).ToList()
            };
            return View(vm);
        }
        
        [HttpGet("Users")]
        public IActionResult Users()
        {
            var allProviders = _authService.GetAllAuthProvidersDB();
            var allRoles = _authService.GetAllRoles();
            var vm = _authService.GetAllIdentities().Select(x =>
            {
                var providers = allProviders.Where(a => a.IdentityId == x.Id).ToList();
                var roles = allRoles.Where(a => a.AuthId == x.Id).ToList();
                return new IdentityViewModel() {Identity = x, AuthProviders = providers, Roles = roles};
            }).ToList();
            
            return View(vm);
        }
        
        [HttpGet("EmailExist")]
        public IActionResult EmailExist(string email)
        {
            var allProviders = _authService.GetAllAuthProvidersDB();
            return new JsonResult(new
            {
                Exist = allProviders.FirstOrDefault(x => x.Email == email) != null
            });
        }
        
        [HttpPost("Login")]
        public IActionResult Login(LoginViewModel model)
        {
            AuthProviderType authtype = AuthProviderType.Basic;
            if (model.IsFacebookAuth)
            {
                authtype = AuthProviderType.Facebook;
            }
            
            var provider = _authService.GetAuthProvider(authtype, model.Email, model.Password);

            if (provider == null)
            {
                ViewBag.Message = "Error login";
                return View();
            }

            return RedirectToAction("SuccessRedirect", new { id = provider.IdentityId, email = provider.Email, authType = provider.Type, redirectUrl = model.RedirectUrl});
        }

        [HttpPost("Register")]
        public IActionResult Register(RegisterViewModel model)
        {
            if (!string.IsNullOrEmpty(model.Email))
            {
                var i = _authService.GetAllIdentities();

                var newIdentity = new Identity
                {
                    Id = i.Max(x => x.Id) + 1,
                    Token = Guid.NewGuid(),
                };
                var basicProvier = new AuthProvider
                {
                    Email = model.Email,
                    IdentityId = newIdentity.Id,
                    Type = AuthProviderType.Basic
                };
                _authService.GetAllIdentities().Add(newIdentity);
                _authService.GetAllAuthProvidersDB().Add(basicProvier);
                
                return new JsonResult(new{ id = newIdentity.Id });

            }

            return BadRequest();
        }

        [HttpGet("SetPassword")]
        public IActionResult SetPassword(string token, bool success)
        {
            var claimsPrincipal = GetValidatedClaims(token);
            if (claimsPrincipal == null)
            {
                return BadRequest();
            }

            var redirectUrlClaim = claimsPrincipal.Claims.FirstOrDefault(x => x.Type == "RedirectUrl");
            var idClaim = claimsPrincipal.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier);
            
            return View(new SetPasswordViewModel
            {
                Id = int.Parse(idClaim.Value),
                RedirectUrl = redirectUrlClaim.Value
            });
        }
        
        [HttpGet("SetPasswordSuccess")]
        public IActionResult SetPasswordSuccess(string redirectUrl)
        {
            return View(new SetPasswordViewModel
            {
                RedirectUrl = redirectUrl
            });
        }
        
        [HttpPost("SetPassword")]
        public IActionResult SetPassword(SetPasswordViewModel model)
        {
            var provider = _authService.GetAllAuthProvidersDB().FirstOrDefault(x => x.Type == AuthProviderType.Basic && x.IdentityId == model.Id);
            if (provider != null)
            {
                provider.Password = model.Password;
                return RedirectToAction("SetPasswordSuccess",new{ redirectUrl = model.RedirectUrl });

            }

            return RedirectToAction("SetPassword",new{ id = model.Id, redirectUrl = model.RedirectUrl });
        }

        [HttpGet("SuccessRedirect")]
        public IActionResult SuccessRedirect(int id, string email, AuthProviderType authType, string redirectUrl)
        {
            var token = _authService.GenerateToken(id, email, authType, _authService.GetAllRoles().Where(x => x.AuthId == id).ToList(), DateTime.UtcNow.AddDays(7));

            Response.Cookies.Append($"session-{Guid.NewGuid()}", token);
            
            ViewBag.RedirectUrl = $"{redirectUrl}?token={token}";
            return View();
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
        
        private ClaimsPrincipal GetValidatedClaims(string token)
        {
            var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(AuthService.Secret));

            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                return tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = AuthService.AuthSiteAudience,
                    ValidAudience = AuthService.AuthServerIssuer,
                    IssuerSigningKey = mySecurityKey
                }, out SecurityToken validatedToken);
            }
            catch {}
            return null;
        }
        
        private ClaimsPrincipal GetValidatedOwnClaims(string token)
        {
            var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(AuthService.Secret));

            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                return tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    IssuerSigningKey = mySecurityKey
                }, out SecurityToken validatedToken);
            }
            catch {}
            return null;
        }
    }
}