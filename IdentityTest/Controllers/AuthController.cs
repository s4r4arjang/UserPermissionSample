using IdentityTest.Context;
using IdentityTest.Models;
using IdentityTest.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;

namespace IdentityTest.Controllers
{

    public record RegisterRequest(string Username, string Password);
    public record LoginRequest(string Username, string Password);

    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _db;
        private readonly IUserPermissionService _permService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(AppDbContext db, IUserPermissionService permService , ILogger<AuthController> logger)
        {
            _db = db;
            _permService = permService;
            this._logger = logger;
        }

        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
                return BadRequest("username/password required");

            var exists = await _db.Users.AnyAsync(u => u.Username == request.Username);
            if (exists) return BadRequest("Username already exists");

            var user = new User
            {
                Username = request.Username,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
                IsActive = true
            };
            _db.Users.Add(user);
            await _db.SaveChangesAsync();

            return Ok(new { message = "registered" });
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var user = await _db.Users.FirstOrDefaultAsync(u => u.Username == request.Username && u.IsActive);

            if (user == null)
                return Unauthorized(new { message = "user not found" });

            if (!BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
                return Unauthorized(new { message = "wrong password", dbHash = user.PasswordHash });

            var permissions = await _permService.GetPermissionsAsync(user.Id);
            _logger.LogInformation("Permissions for user {User}: {Perms}", user.Username, string.Join(",", permissions));
            var claims = new List<Claim>
    {
        new(ClaimTypes.NameIdentifier, user.Id.ToString()),
        new(ClaimTypes.Name, user.Username)
    };
            claims.AddRange(permissions.Select(p => new Claim("permission", p)));

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);
           
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddHours(8)
            });

            return Ok(new { message = "logged in", permissions });
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Ok(new { message = "logged out" });
        }

        [HttpGet("me")]
        public IActionResult Me()
        {
            if (!User.Identity?.IsAuthenticated ?? true) return Unauthorized();
            var perms = User.Claims.Where(c => c.Type == "permission").Select(c => c.Value).ToList();
            return Ok(new { user = User.Identity!.Name, permissions = perms });
        }


        [HttpGet("test-bcrypt")]
        public IActionResult TestBcrypt()
        {
            string password = "123456";
            string dbHash = "$2a$11$XGgpe8N7RTU9XXsCqhRek.2LMJskmTn7neeCz5A6HRjnln5MHHCYS";

            bool isValid = BCrypt.Net.BCrypt.Verify(password, dbHash);

            return Ok(new { isValid });
        }
    }
}
