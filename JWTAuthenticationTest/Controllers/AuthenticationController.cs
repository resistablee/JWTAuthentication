using JWTAuthenticationTest.DTO;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace JWTAuthenticationTest.Controllers
{
    [AllowAnonymous]
    public class AuthenticationController : Controller
    {
        private readonly Services.AuthenticationService _authenticationService;

        public AuthenticationController()
        {
            _authenticationService = new Services.AuthenticationService();
        }

        [HttpGet("/login")]
        public IActionResult Login([FromQuery] string returnUrl = null)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        [HttpPost("/login")]
        public IActionResult Login([FromForm] LoginDTO request, string returnUrl = null)
        {
            var userRole = _authenticationService.Login(request);

            if (string.IsNullOrEmpty(userRole))
            {
                return BadRequest("Invalid credentials");
            }

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Role, userRole),
                new Claim(JwtRegisteredClaimNames.Email, request.Email),
                new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.Now).ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));

            if (string.IsNullOrEmpty(returnUrl))
                return RedirectToAction("Index", "Home");

            return Redirect(returnUrl);
        }

        [HttpGet("/register")]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost("/register")]
        public IActionResult Register([FromForm] RegisterDTO request)
        {
            return Ok(request);
        }

        [HttpGet("/logout")]
        [Authorize]
        public IActionResult Logout()
        {
            HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Index", "Home");
        }
    }
}