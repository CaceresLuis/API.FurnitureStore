using System.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Identity;
using API.FurnitureStore.Shared.DTOs;
using API.FurnitureStore.Shared.Auth;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using API.FurnitureStore.API.Configoration;

namespace API.FurnitureStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly JwtConfig _jwtConfig;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public AuthenticationController(IOptions<JwtConfig> jwtConfig, UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            _jwtConfig = jwtConfig.Value;
            _userManager = userManager;
            _signInManager = signInManager;
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
                UserName = request.EmailAddress
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

            string token = GenerateToken(user);
            return Ok(new AuthResult()
            {
                Status = true,
                Token = token
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
    }
}
