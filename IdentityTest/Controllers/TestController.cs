using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace IdentityTest.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class TestController : ControllerBase
    {
        [HttpGet("open")]
        [AllowAnonymous]
        public IActionResult Open() => Ok(new { message = "no auth needed" });

        [HttpGet("secure-read")]
        [Authorize(Policy = "Permission:books.read")]
        public IActionResult SecureRead() => Ok(new { message = "you can read books" });

        [HttpPost("secure-write")]
        [Authorize(Policy = "Permission:books.write")]
        public IActionResult SecureWrite() => Ok(new { message = "you can write books" });
    }
}
