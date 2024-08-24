using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers;

public class AccountController(DataContext context, ITokenService tokenService) : BaseApiController
{
    [HttpPost("Register")]
    public async Task<ActionResult<UserDTO>> Register(RegisterDTO userObj)
    {
        if (await UserExists(userObj.Username)) { return BadRequest("Username taken!"); }
        using var hmac = new HMACSHA512();
        var passHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(userObj.Password));
        var passSalt = hmac.Key;
        var user = new AppUser
        {
            UserName = userObj.Username,
            PasswordHash = passHash,
            PasswordSalt = passSalt,
        };

        context.Users.Add(user);
        await context.SaveChangesAsync();

        return new UserDTO{
            Username = userObj.Username,
            Token = tokenService.CreateToken(user)
        };
    }

    [HttpPost("Login")]
    public async Task<ActionResult<UserDTO>> Login(LoginDTO loginObj)
    {
        var user = await context.Users.FirstOrDefaultAsync(x => x.UserName == loginObj.Username);
        if (user == null) return Unauthorized("Invalid User");

        using var hmac = new HMACSHA512(user.PasswordSalt);
        var passHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginObj.Password));
        for (int i = 0; i < passHash.Length; i++)
        {
            if (passHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password");
        }

        return Ok(new UserDTO{
            Username = user.UserName,
            Token = tokenService.CreateToken(user)
        });
    }

    public async Task<bool> UserExists(string username)
    {
        return await context.Users.AnyAsync(x => x.UserName.ToLower() == username.ToLower());
    }
}
