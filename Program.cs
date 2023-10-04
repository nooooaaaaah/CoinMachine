using CoinMachine;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.Extensions.Logging;
using System;
using System.IdentityModel.Tokens.Jwt;

namespace StoreMeDaddy
{
    class Program
    {
        public class TestUser : IUser
        {
            public int UserID => 1;
            public string Username => "testuser";
            public string Role => "admin";
        }

        static void Main(string[] args)
        {
            List<string> possibleRoles = new() { "Admin", "User" };
            string secretKey = "your-secret-key-with-16bytes";
            string issuer = "your-issuer";
            int expiryMinutes = 60;

            ILoggerFactory loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            ILogger<TokenService> logger = loggerFactory.CreateLogger<TokenService>();

            TokenService tokenService = new(secretKey, issuer, expiryMinutes, possibleRoles);

            IUser user = new TestUser();

            string token = tokenService.GenerateToken(user);

            Console.WriteLine($"Generated Token: {token}");
            JwtSecurityTokenHandler jwtHandler = new();
            Console.WriteLine($"token: {jwtHandler.ReadJwtToken(token)}");

        }
    }
}
