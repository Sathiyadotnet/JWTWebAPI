using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JWTWebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static UserRegister userRegister = new UserRegister();
        private readonly IConfiguration? _configuration;
        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }


        [HttpPost("Register")]
        public async Task<ActionResult<UserRegister>> Register(UserDto request)
        {
            CreatePasswordHash(request.password, out byte[] passwordHash, out byte[] passwordSalt);

            userRegister.UserName = request.username;
            userRegister.PasswordHash = passwordHash;
            userRegister.PasswordSalt = passwordSalt;

            return Ok(userRegister);
        }

        [HttpPost("Login")]
        public async Task<ActionResult<string>> Login(UserDto request)
        {
            if(userRegister.UserName != request.username)
            {
                return BadRequest("User not found");
            }
            if(!VerifyPasswordHash(request.password,userRegister.PasswordHash,userRegister.PasswordSalt))
            {
                return BadRequest("Wrong Password");
            }
            string token = CreateToken(userRegister);
            return Ok(token);
        }
        private string CreateToken(UserRegister userRegister)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name,userRegister.UserName)
            };
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(s: _configuration.GetSection("AppSettings:Token").Value));
            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred);
               var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }
        private void CreatePasswordHash(string password,out byte[] passwordHash, out byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }
        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA512(userRegister.PasswordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }

    }
}
