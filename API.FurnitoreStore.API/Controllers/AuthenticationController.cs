using API.FurnitoreStore.API.Configuration;
using API.FurnitoreStore.API.Services;
using API.FurnitoreStore.Share.Auth;
using API.FurnitoreStore.Share.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Bcpg;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using static System.Net.WebRequestMethods;

namespace API.FurnitoreStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JWTConfig _jwtConfig;
        private readonly IEmailSender _emailSender;

        public AuthenticationController(UserManager<IdentityUser> userManager, 
                                        IOptions<JWTConfig> jwtConfig, 
                                        IEmailSender emailSender)
        {
            _userManager = userManager;
            _jwtConfig = jwtConfig.Value;
            _emailSender = emailSender;
        }

        [HttpPost ("Register")]
        [AllowAnonymous]
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
                UserName = request.EmailAddress,
                EmailConfirmed=false
            };

            var isCreated = await _userManager.CreateAsync(user,request.Password);

            if (isCreated.Succeeded)
            {
                await SendVerificationEmail(user);

                return Ok(new AuthResult()
                {
                    Result = true,
                    Errors = new List<string>() 
                    {
                        "To continue your email must be confirmed"
                    }
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

        }

        [HttpPost("Login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] UserLoginRequestDto request)
        { 
            if (!ModelState.IsValid) return BadRequest();

            //Check if user exist
            var existingUser = await _userManager.FindByEmailAsync(request.Email);

            if (existingUser == null)
                return BadRequest(new AuthResult
                {
                    Errors = new List<string> {"Invalid Payload"},
                    Result = false
                });

            if (!existingUser.EmailConfirmed)
                return BadRequest(new AuthResult
                {
                    Errors = new List<string> { "Email must be verified" },
                    Result = false
                });


            var checkUserAndPass = await _userManager.CheckPasswordAsync(existingUser, request.Password);

            if (!checkUserAndPass) return BadRequest(new AuthResult 
            { 
                Errors = new List<string> {"Invalid credentials"},
                Result = false
            });

            var token = GenerateToken(existingUser);

            return Ok(new AuthResult { Result = true, Token = token }); 
        }

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code))
            {
                return BadRequest(new AuthResult
                {
                    Result = false,
                    Errors = new List<string> { "Invalid email confirmation URL." }
                });
            }

            var user = await _userManager.FindByIdAsync(userId);

            if (user is null)
            {
                return NotFound($"Unable to load user with id {userId}");
            }

            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));

            var result = await _userManager.ConfirmEmailAsync(user, code);

            var status = result.Succeeded ? "Thank you for confirming your email" : 
                                            "There has been an error confirming your email";

            return Ok(status);
        }

        private string GenerateToken(IdentityUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler(); //Es la clase que va a crear el token propiamente dicho
            var key = Encoding.UTF8.GetBytes(_jwtConfig.Secret);

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new ClaimsIdentity(new[]
                {
                    new Claim("Id", user.Id),
                    new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Sub, user.Email),
                    new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), //Hace referencia a JWT Id. Es el ID del Token en sí.
                    new Claim(Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString())
                })),
                Expires = DateTime.UtcNow.Add(_jwtConfig.ExpiryTime),
                SigningCredentials = new SigningCredentials (new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);

            return jwtTokenHandler.WriteToken(token);
        }

        private async Task SendVerificationEmail(IdentityUser user)
        {
            var verificationCode = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            verificationCode = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(verificationCode));

            //example: https://localhost:8080/api/authentication/verifyemail/userId=exampleuserId&code=examplecode
            var callbackUrl = $@"{Request.Scheme}://{Request.Host}{Url.Action("ConfirmEmail", controller: "Authentication",
                new { userId = user.Id, code = verificationCode })}";


            var emailBody = $@"<h3> Verify email account </h3> <br> 
                            <p> Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'> <b>clicking here </b></a> </p>";

           await _emailSender.SendEmailAsync(user.Email, "Verify account", emailBody);

            Console.WriteLine(callbackUrl);

        }

        
    }
}
