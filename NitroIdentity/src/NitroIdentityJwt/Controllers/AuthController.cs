using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using NitroIdentityJwt.Dtos;
using NitroIdentityJwt.Models;
using NitroIdentityJwt.Service;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace NitroIdentityJwt.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IConfiguration _configuration;

    public AuthController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IConfiguration configuration)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _configuration = configuration;
    }


    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterDto model)
    {
        var user = new ApplicationUser { 
            NationalId = model.NationalId,
            PostalCode = model.PostalCode,
            BourseCode = model.BourseCode,
            UserName = model.NationalId, 
            Email = model.Email, 
            EmailConfirmed = true,
            PhoneNumberConfirmed = true,
        };
        var result = await _userManager.CreateAsync(user, model.Password);

        if (result.Succeeded)
        {
            await _userManager.AddToRoleAsync(user, "User");
            var permissions  = new List<string> { Permissions.CreateTerm, Permissions.UpdateTerm, Permissions.DeleteTerm };
            foreach (var permission in permissions)
            {
                await _userManager.AddClaimAsync(user, new Claim("permissions", permission));
            }

            //await _userManager.AddClaimAsync(user, new Claim("permissions", Permissions.CreateTerm));
            //await _userManager.AddClaimAsync(user, new Claim("permissions", Permissions.UpdateTerm));
            return Ok(new { Message = "User registered successfully" });
        }

        return BadRequest(result.Errors);
    }


    //[HttpPost("login")]
    //public async Task<IActionResult> Login([FromBody] LoginDto model)
    //{
    //    //???????????????? cahnage NationalId tgo UserName
    //    var result = await _signInManager.PasswordSignInAsync(model.NationalId, model.Password, false, false);

    //    if (result.Succeeded)
    //    {
    //        var user = await _userManager.FindByEmailAsync(model.NationalId);
    //        var token = GenerateJwtToken(user);
    //        return Ok(new { Token = token });
    //    }

    //    return Unauthorized();
    //}


    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginDto model)
    {
        //???????????????? cahnage To NationalId
        var user = await _userManager.FindByNameAsync(model.NationalId);
        if (user == null)
        {
            return Unauthorized();
        }
        
        //    var result = await _signInManager.PasswordSignInAsync(model.NationalId, model.Password, false, false);
        var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);
        if (result.Succeeded)
        {
            var token = await GenerateJwtToken(user);
            var refreshToken = GenerateRefreshToken();

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);
            await _userManager.UpdateAsync(user);

            HttpContext.Session.SetString("Token", token);
            Response.Cookies.Append("RefreshToken", refreshToken, new CookieOptions { HttpOnly = true });

            return Ok(new { Token = token, RefreshToken = refreshToken });
        }

        return Unauthorized();
    }


    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken(RefreshTokenDto model)
    {
        var user = await _userManager.FindByNameAsync(model.NationalId);
        //var user2 = await _userManager.GetUserAsync(model.Email);
        if (user == null || user.RefreshToken != model.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
        {
            return BadRequest("Invalid refresh token");
            //return Unauthorized();
        }
        var currentToken = HttpContext.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");

        var newToken = await GenerateJwtToken(user);
        var newRefreshToken = GenerateRefreshToken();

        user.RefreshToken = newRefreshToken;
        await _userManager.UpdateAsync(user);

        return Ok(new { Token = newToken, RefreshToken = newRefreshToken });
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword(ForgotPasswordDto model)
    {
        var user = await _userManager.FindByEmailAsync(model.Email);
        if (user == null)
        {
            return BadRequest("User not found");
        }

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        // Send email with reset token

        return Ok("Password reset email sent");
    }

    //private string GenerateJwtToken(ApplicationUser user)
    //{
    //    var jwtSettings = _configuration.GetSection("JwtSettings");
    //    var key = Encoding.ASCII.GetBytes(jwtSettings["Secret"]);

    //    var claims = new[]
    //    {
    //            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
    //            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    //        };

    //    var token = new JwtSecurityToken(
    //        issuer: jwtSettings["Issuer"],
    //        audience: jwtSettings["Audience"],
    //        claims: claims,
    //        expires: DateTime.UtcNow.AddMinutes(double.Parse(jwtSettings["ExpiryMinutes"])),
    //        signingCredentials: new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
    //    );

    //    return new JwtSecurityTokenHandler().WriteToken(token);
    //}

    private async Task<string> GenerateJwtToken(ApplicationUser user)
    {
        var jwtSettings = _configuration.GetSection("JwtSettings");
        //var key = Encoding.ASCII.GetBytes(jwtSettings["Secret"]);

        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id)
        };

        // Add roles to claims
        var roles = await _userManager.GetRolesAsync(user);
        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        // Add permissions to claims if necessary
        // This depends on how you've implemented permissions in your system

        var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtSettings["Secret"]));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expires = DateTime.Now.AddMinutes(Convert.ToDouble(jwtSettings["ExpireMinutes"]));

        var token = new JwtSecurityToken(
            issuer: jwtSettings["Issuer"],
            audience: jwtSettings["Audience"],
            claims,
            expires: expires,
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }


    [HttpPost("update-user-role")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> UpdateUserRole(string userId, string newRole)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return NotFound("User not found");

        var currentRoles = await _userManager.GetRolesAsync(user);
        await _userManager.RemoveFromRolesAsync(user, currentRoles);
        await _userManager.AddToRoleAsync(user, newRole);

        // Update permissions if necessary
        // This depends on how you've implemented permissions in your system

        return Ok("User role updated successfully");
    }
}
