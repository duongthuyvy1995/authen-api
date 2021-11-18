using EntityFramework.Models;
using EntityFramework.Service;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace EntityFramework.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class IdentityController : ControllerBase
    {

        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailSender _emailSender;
        private readonly IConfiguration _configuration;

        public IdentityController(UserManager<IdentityUser> userManager, 
            SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager, 
            IEmailSender emailSender,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _emailSender = emailSender;
            _configuration = configuration;
        }

        [HttpGet]
        public IActionResult Test()
        {
            return Ok(true);
        }

        [HttpPost]
        public async Task<IActionResult> Signup([FromBody] SignUpViewModel model)
        {
            //if (ModelState.IsValid)
            //{
                if (!(await _roleManager.RoleExistsAsync(model.Role)))
                {
                    var role = new IdentityRole { Name = model.Role };
                    var roleResult = await _roleManager.CreateAsync(role);
                    if (!roleResult.Succeeded)
                    {
                        var errors = roleResult.Errors.Select(s => s.Description);
                        ModelState.AddModelError("Role", string.Join(",", errors));
                        return Ok(model);
                    }
                }


                if ((await _userManager.FindByEmailAsync(model.Email)) == null)
                {
                    var user = new IdentityUser
                    {
                        Email = model.Email,
                        UserName = model.Email
                    };

                    var result = await _userManager.CreateAsync(user, model.Password);
                    if (result.Succeeded)
                    {
                        var claim = new Claim("Department", model.Department);
                        await _userManager.AddClaimAsync(user, claim);
                        await _userManager.AddToRoleAsync(user, model.Role);
                        return RedirectToAction("Signin");
                    }

                    ModelState.AddModelError("Signup", string.Join("", result.Errors.Select(x => x.Description)));
                    return Ok(model);
                }
            //}

            return Ok(model);
        }


        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                return RedirectToAction("Signin");
            }

            return new NotFoundResult();
        }
        public IActionResult Signin()
        {
            return Ok(new SignInViewModel());
        }

        [HttpPost]
        public async Task<IActionResult> Signin(SignInViewModel model)
        {
            if (ModelState.IsValid)
            {
                var issuer = _configuration["Tokens:Issuer"];
                var audience = _configuration["Tokens:Audience"];
                var key = _configuration["Tokens:Key"];
                var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberMe, false);
                if (result.Succeeded)
                {

                    var user = await _userManager.FindByEmailAsync(model.Username);

                    var userClaims = await _userManager.GetClaimsAsync(user);
                    var role = await _userManager.GetRolesAsync(user);

                    var claims = new[]
                        {
                            new Claim(JwtRegisteredClaimNames.Email , user.Email),
                            new Claim(JwtRegisteredClaimNames.Jti , user.Id),
                        };
                    userClaims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
                    userClaims.Add(new Claim(JwtRegisteredClaimNames.Jti, user.Id));
                    userClaims.Add(new Claim(ClaimTypes.Role, role.FirstOrDefault()));
                    var test = await _userManager.IsInRoleAsync(user, "Admin");
                    var keyBytes = Encoding.UTF8.GetBytes(key);
                    var theKey = new SymmetricSecurityKey(keyBytes);
                    var creds = new SigningCredentials(theKey, SecurityAlgorithms.HmacSha256);
                    var token = new JwtSecurityToken(issuer, audience, userClaims, expires: DateTime.Now.AddMinutes(30), signingCredentials: creds);

                    return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token),
                                    email = user.Email,
                                    role = role.FirstOrDefault(),
                                    department = userClaims[0].Value,
                                    expiresIn = 30*3600,
                                    userId = user.Id
                    });
                    //if (await _userManager.IsInRoleAsync(user, "Member"))
                    //{
                        
                    //    //return RedirectToAction("Member", "Home");
                    //}
                }
                else
                {
                    ModelState.AddModelError("Login", "Cannot login.");
                }
            }
            return Ok(true);
        }

        public async Task<IActionResult> AccessDenied()
        {
            return Ok();
        }

        public async Task<IActionResult> Signout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Signin");
        }
    }
}
