using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DataAccessLayer.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using ServiceLayer.Person;
using Twilio.Rest.Verify.V2.Service;
using WebAPI.Filters;
using WebAPI.Models;
using WebAPI.Models.Account;

namespace WebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly IPersonService personService;
        private readonly IConfiguration config;
        public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, IConfiguration config, IPersonService personService)
        {
            this.config = config;
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.personService = personService;
        }

        [AllowAnonymous]
        [HttpPost]
        [Route("register")]
        [RequestLimit("Test-Action", NoOfRequest = 5, Seconds = 10)]
        public async Task<IActionResult> Register([FromBody] RegisterUserResource registerUser)
        {
            if (!ModelState.IsValid)
                return BadRequest(0);

            var user = new ApplicationUser
            {
                UserName = registerUser.UserName,
                PhoneNumber = registerUser.Phone
            };

            var result = await userManager.CreateAsync(user, registerUser.Password);

            if (result.Succeeded)
            {
                var createdUser = await userManager.FindByNameAsync(registerUser.UserName);
                personService.AddPerson(createdUser);
                await SendCode(createdUser.PhoneNumber);
                return Ok(new APIResponse { bit = true });
            }
            else
            {
                return BadRequest(new APIResponse { bit = false });
            }
        }
        private async Task<bool> SendCode(string PhoneNumber)
        {
            try
            {
                var verification = await VerificationResource.CreateAsync(
                   to: "+2" + PhoneNumber,
                   channel: "sms",
                   pathServiceSid: config["Twilio:VerificationServiceSID"]
               );

                if (verification.Status == "pending")
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }
            
        }
      
        [HttpPost]
        [Route("verify")]
        public async Task<IActionResult> verify([FromBody] VerifyUserResource verifyUserResource)
        {
            if (!ModelState.IsValid)
                return BadRequest(0);

            var user = await userManager.FindByNameAsync(verifyUserResource.UserName);
            try
            {
                var verification = await VerificationCheckResource.CreateAsync(
                    to: "+2"+verifyUserResource.Phone,
                    code: verifyUserResource.OTP,
                    pathServiceSid: config["Twilio:VerificationServiceSID"]
                );
                if (verification.Status == "approved")
                {
                    user.PhoneNumberConfirmed = true;
                    await userManager.UpdateAsync(user);
                    var tokenString = GenerateJSONWebToken(user);
                    return Ok(new { token = tokenString });
                }
                else
                {
                    return BadRequest(new APIResponse { bit = false });
                }
            }
            catch (Exception ex)
            {
                return BadRequest(new APIResponse { bit = false });
            }
            
        }
        [AllowAnonymous]
        [HttpPost]
        [Route("login")]
        [RequestLimit("Test-Action", NoOfRequest = 5, Seconds = 10)]
        public async Task<IActionResult> Login([FromBody] UserResource loginUser)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);


            var result = await signInManager.PasswordSignInAsync(loginUser.UserName, loginUser.Password,false,false);

            if (!result.Succeeded)
            {
                ModelState.AddModelError("", "Invalid Login");
                return BadRequest(ModelState);
            }
            else
            {
                var user = await userManager.FindByNameAsync(loginUser.UserName);
                var tokenString = GenerateJSONWebToken(user);
                return Ok(new { token = tokenString });
            }
        }

        private string GenerateJSONWebToken(ApplicationUser userInfo)
        {
            try
            {
                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]));
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
                var roles = userManager.GetRolesAsync(userInfo);
                var claims = new[] {
                                    new Claim("Username", userInfo.UserName),
                                    new Claim("PhoneNumber", userInfo.PhoneNumber),
                                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                                };

                var token = new JwtSecurityToken(config["Jwt:Issuer"],
                  config["Jwt:Issuer"],
                  claims,
                  expires: DateTime.Now.AddMinutes(120),
                  signingCredentials: credentials);

                return new JwtSecurityTokenHandler().WriteToken(token);
            }
            catch (Exception)
            {

                return "";
            }
            
        }


    }
}
