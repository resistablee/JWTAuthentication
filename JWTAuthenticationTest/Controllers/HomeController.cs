using JWTAuthenticationTest.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;

namespace JWTAuthenticationTest.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        [Authorize(Roles = Roles.Teacher)]
        public IActionResult Test()
        {
            return View();
        }

        [Authorize(Roles = Roles.Student)]
        public IActionResult TestStudent()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [HttpGet("/AccessDenied")]
        public IActionResult AccessDenied([FromQuery] string returnUrl = null)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}