using JWTAuthenticationTest.DTO;
using JWTAuthenticationTest.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWTAuthenticationTest.Services
{
    public class AuthenticationService
    {
        public string? Login(LoginDTO request)
        {
            if (request.Email == "selman@onlineedu.com.tr" && request.Password == "123")
            {
                string token = GenerateJWTToken(request.Email, Roles.Teacher);
                return Roles.Teacher;
            }
            else if (request.Email == "altan@onlineedu.com.tr" && request.Password == "123")
            {
                string token = GenerateJWTToken(request.Email, Roles.Student);
                return Roles.Student;
            }

            return null;
        }

        public bool Register(RegisterDTO request)
        {
            return true;
        }

        // This method should generate a JWT token
        private string GenerateJWTToken(string email, string role)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Role, role),
                new Claim(JwtRegisteredClaimNames.Email, email),
                new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.Now).ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("superSecretKey@345-superSecretKey@345_superSecretKey@345-superSecretKey@345?"));
            var credential = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                               issuer: "Online Education",
                               audience: email,
                               claims: claims,
                               expires: DateTime.Now.AddHours(2),
                               signingCredentials: credential);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}