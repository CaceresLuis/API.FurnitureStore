using System.Text;
using System.Security.Claims;
using API.FurnitureStore.Data;
using Microsoft.AspNetCore.Mvc;
using System.Text.Encodings.Web;
using API.FurnitureStore.Shared;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using API.FurnitureStore.Shared.DTOs;
using API.FurnitureStore.Shared.Auth;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using API.FurnitureStore.Shared.Common;
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
        private readonly APIFurnitureContext _context;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly TokenValidationParameters _tokenValidationParameters;

        private readonly ILogger<AuthenticationController> _logger;

        public AuthenticationController(IOptions<JwtConfig> jwtConfig, UserManager<IdentityUser> userManager, IEmailSender emailSender, APIFurnitureContext context, TokenValidationParameters tokenValidationParameters, ILogger<AuthenticationController> logger)
        {
            _logger = logger;
            _context = context;
            _userManager = userManager;
            _emailSender = emailSender;
            _jwtConfig = jwtConfig.Value;
            _tokenValidationParameters = tokenValidationParameters;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationRequestDto request)
        {
            if (!ModelState.IsValid) return BadRequest();

            IdentityUser emailExist = await _userManager.FindByEmailAsync(request.EmailAddress);
            if (emailExist != null)
            {
                _logger.LogError("A user is traying to register: Email Already exist");
                return BadRequest(new AuthResult
                {
                    Status = false,
                    Errors = new List<string>()
                    {
                        "Email Already exist"
                    }
                });
            }

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

                string message = $"A user is traying to register: {errors.FirstOrDefault()}";
                _logger.LogError(message);
                return BadRequest(new AuthResult
                {
                    Status = false,
                    Errors = errors
                });
            }

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
            if (existeingUser is null)
                return BadRequest(new AuthResult
                {
                    Status = false,
                    Errors = new List<string> { "Invalid Payload" }
                });

            if (!existeingUser.EmailConfirmed)
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

            return Ok(GenerateTokenAsync(existeingUser));
        }

        [HttpPost("Refreshtoken")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequest tokenRequest)
        {
            if (!ModelState.IsValid)
                return BadRequest(new AuthResult
                {
                    Errors = new List<string> { "Invalid parameters" },
                    Status = false
                });

            AuthResult result = await VerifyAndGenerateTokenAsync(tokenRequest);
            if (result is null)
                return BadRequest(new AuthResult
                {
                    Errors = new List<string> { "Invalid token" },
                    Status = false
                });

            return Ok(result);
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

            if (user is null)
                return NotFound($"Unable to load user with '{userId}'. ");

            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));

            IdentityResult result = await _userManager.ConfirmEmailAsync(user, code);
            string status = result.Succeeded ? "Thank you for confirm your email." : "There has been an error confirming your email.";

            return Ok(status);
        }

        private async Task<AuthResult> GenerateTokenAsync(IdentityUser user)
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
                Expires = DateTime.UtcNow.Add(_jwtConfig.Expirytime),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };

            SecurityToken token = jwtTokenHandler.CreateToken(tokenDescriptor);

            string jwtToken = jwtTokenHandler.WriteToken(token);

            RefreshToken refreshToken = new RefreshToken
            {
                JwtId = token.Id,
                Token = RandomGenerator.GenerateRandomString(23),
                AddedDate = DateTime.UtcNow,
                ExpiryDate = DateTime.UtcNow.AddDays(30),
                IsRevoked = false,
                IsUsed = false,
                UserId = user.Id
            };

            await _context.RefreshTokens.AddAsync(refreshToken);
            await _context.SaveChangesAsync();

            return new AuthResult
            {
                Token = jwtToken,
                RefreshToken = refreshToken.Token,
                Status = true
            };
        }

        private async Task SendVerificationEmail(IdentityUser user)
        {
            string verificationCode = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            verificationCode = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(verificationCode));

            string callackUrl = $"{Request.Scheme}://{Request.Host}{Url.Action("ConfirmEmail", controller: "Authentication", new { userId = user.Id, code = verificationCode })}";

            string verificationLink = $"{HtmlEncoder.Default.Encode(callackUrl)}";
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


        private async Task<AuthResult> VerifyAndGenerateTokenAsync(TokenRequest tokenRequest)
        {
            JwtSecurityTokenHandler jwtTokenHandler = new();
            try
            {
                _tokenValidationParameters.ValidateLifetime = false;

                ClaimsPrincipal tokenBeingVerified = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParameters, out SecurityToken? validatedToken);

                if (validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    bool result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);

                    if (!result || tokenBeingVerified == null)
                        throw new Exception("Invalid Token");
                }

                long utcExpiryDate = long.Parse(tokenBeingVerified.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Exp).Value);

                DateTime expiryDate = DateTimeOffset.FromUnixTimeSeconds(utcExpiryDate).UtcDateTime;
                if (expiryDate < DateTime.UtcNow)
                    throw new Exception("Token Expired");


                /*var storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.Token == tokenRequest.RefreshToken);
                if (storedToken is null)
                    throw new Exception("Invalid Token");*/
                //This is the same as the previous comment
                RefreshToken storedToken = await _context.RefreshTokens.FirstOrDefaultAsync(t => t.Token == tokenRequest.RefreshToken) ?? throw new Exception("Invalid Token");

                if (storedToken.IsRevoked || storedToken.IsUsed)
                    throw new Exception("Invalid Token");

                string jti = tokenBeingVerified.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti).Value;
                if (jti != storedToken.JwtId)
                    throw new Exception("Invalid Token");

                if (storedToken.ExpiryDate < DateTime.UtcNow)
                    throw new Exception("Token Expired");

                storedToken.IsUsed = true;
                _context.RefreshTokens.Update(storedToken);
                await _context.SaveChangesAsync();

                IdentityUser dbuser = await _userManager.FindByIdAsync(storedToken.UserId);

                return await GenerateTokenAsync(dbuser);
            }
            catch (Exception e)
            {
                string message = e.Message == "Invalid Token" || e.Message == "Token Expired" ? e.Message : "Internal Error";

                return new AuthResult() { Status = false, Errors = new List<string> { message } };
            }
        }
    }
}
