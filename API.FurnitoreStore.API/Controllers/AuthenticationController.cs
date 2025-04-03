using API.FurnitoreStore.API.Configuration;
using API.FurnitoreStore.Share.Auth;
using API.FurnitoreStore.Share.DTOs;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace API.FurnitoreStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JWTConfig _jwtConfig;

        public AuthenticationController(UserManager<IdentityUser> userManager, IOptions<JWTConfig> jwtConfig)
        {
            _userManager = userManager;
            _jwtConfig = jwtConfig.Value;
        }

        public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDto request) 
        {
            if (!ModelState.IsValid) return BadRequest();

            //Verify if email exists
            var emailExists = await _userManager.FindByEmailAsync(request.EmailAddress);

            if (emailExists != null)
                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Email already exists"
                    }
                });

            //Create user
            var user = new IdentityUser()
            {
                Email = request.EmailAddress,
                UserName = request.EmailAddress
            };

            var isCreated = await _userManager.CreateAsync(user);

            if (isCreated.Succeeded)
            {
                var token = GenerateToken(user);
                return Ok(new AuthResult()
                {
                    Result = true,
                    Token = token
                });
            }
            else
            { 
                var errors = new List<string>();
                foreach (var err in isCreated.Errors)
                    errors.Add(err.Description);

                return BadRequest(new AuthResult
                { 
                    Result = false,
                    Errors = errors
                });
            }

            return BadRequest(new AuthResult 
            {
                Result = false,
                Errors = new List<string> { "User couldn't be created" }
            });
        }
    }
}
