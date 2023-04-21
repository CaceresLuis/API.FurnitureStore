using System.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Identity;
using API.FurnitureStore.Shared.DTOs;
using API.FurnitureStore.Shared.Auth;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.WebUtilities;
using API.FurnitureStore.API.Configoration;
using Microsoft.AspNetCore.Identity.UI.Services;

namespace API.FurnitureStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly JwtConfig _jwtConfig;
        private readonly IEmailSender _emailSender;
        private readonly UserManager<IdentityUser> _userManager;

        public AuthenticationController(IOptions<JwtConfig> jwtConfig, UserManager<IdentityUser> userManager, IEmailSender emailSender)
        {
            _jwtConfig = jwtConfig.Value;
            _userManager = userManager;
            _emailSender = emailSender;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDto request)
        {
            if (!ModelState.IsValid) return BadRequest();

            IdentityUser emailExist = await _userManager.FindByEmailAsync(request.EmailAddress);
            if (emailExist != null)
                return BadRequest(new AuthResult
                {
                    Status = false,
                    Errors = new List<string>()
                    {
                        "Email Already exist"
                    }
                });

            IdentityUser user = new()
            {
                Email = request.EmailAddress,
                UserName = request.EmailAddress,
                EmailConfirmed = false
            };

            IdentityResult isCreated = await _userManager.CreateAsync(user, request.Password);
            if (!isCreated.Succeeded)
            {
                List<string> errors = new();
                foreach (IdentityError? err in isCreated.Errors)
                    errors.Add(err.Description);

                return BadRequest(new AuthResult
                {
                    Status = false,
                    Errors = errors
                });
            }

            //string token = GenerateToken(user);

            await SendVerificationEmail(user);
            return Ok(new AuthResult()
            {
                Status = true
            });
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] UserLoginRequestDto request)
        {
            if (!ModelState.IsValid) return BadRequest();

            IdentityUser existeingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existeingUser == null)
                return BadRequest(new AuthResult
                {
                    Status = false,
                    Errors = new List<string> { "Invalid Payload" }
                });

            if(!existeingUser.EmailConfirmed)
                return BadRequest(new AuthResult
                {
                    Status = false,
                    Errors = new List<string> { "Email needs to be confirmed" }
                });

            bool checkUserAndPass = await _userManager.CheckPasswordAsync(existeingUser, request.Password);
            if (!checkUserAndPass)
                return BadRequest(new AuthResult
                {
                    Status = false,
                    Errors = new List<string> { "Invalid Credentials" }
                });

            string token = GenerateToken(existeingUser);

            return Ok(new AuthResult { Status = true, Token = token });
        }

        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code))
                return BadRequest(new AuthResult
                {
                    Status = false,
                    Errors = new List<string> { "Invalid email confirmation url" }
                });

            IdentityUser user = await _userManager.FindByIdAsync(userId);

            if (user == null)
                return NotFound($"Unable to load user with '{userId}'. ");

            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));

            IdentityResult result = await _userManager.ConfirmEmailAsync(user, code);
            string status = result.Succeeded ? "Thank you for confirm your email." : "There has been an error confirming your email.";

            return Ok(status);
        }

        private string GenerateToken(IdentityUser user)
        {
            JwtSecurityTokenHandler jwtTokenHandler = new();
            byte[] key = Encoding.UTF8.GetBytes(_jwtConfig.Secret);
            SecurityTokenDescriptor tokenDescriptor = new()
            {
                Subject = new ClaimsIdentity(new ClaimsIdentity(new[]
                {
                    new Claim("Id", user.Id),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString()),
                })),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };

            SecurityToken token = jwtTokenHandler.CreateToken(tokenDescriptor);

            return jwtTokenHandler.WriteToken(token);
        }

        private async Task SendVerificationEmail(IdentityUser user)
        {
            string verificationCode = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            verificationCode = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(verificationCode));

            string callackUrl = $"{Request.Scheme}://{Request.Host}{Url.Action("ConfirmEmail", controller: "Authentication", new { userId = user.Id, code = verificationCode })}";

            string verificationLink = $"{HtmlEncoder.Default.Encode(callackUrl)}";
            //string emailBody = $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callackUrl)}'> Click here </a> If you don't see it, try crawling :(";
            string emailBody = "<!DOCTYPE html>\n" +
                   "<html>\n" +
                   "<head>\n" +
                   "  <meta charset=\"UTF-8\">\n" +
                   "  <title>Confirm your email</title>\n" +
                   "</head>\n" +
                   "<body>\n" +
                   $"  <p>Please confirm your account by clicking <a href='{verificationLink}'>here</a>. If you cannot click the link, please copy and paste this URL into your browser: {verificationLink}</p>\n" +
                   "</body>\n" +
                   "</html>";

            await _emailSender.SendEmailAsync(user.Email, "Confirm your email", emailBody);
        }
    }
}
