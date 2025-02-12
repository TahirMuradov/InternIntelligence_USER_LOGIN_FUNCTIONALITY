using Bussines.Abstract;
using Entites.DTOs;
using InternIntelligence_USER_LOGIN_FUNCTIONALITY.Model.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace InternIntelligence_USER_LOGIN_FUNCTIONALITY.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase

    {

        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;

        }
     
        
       
        [HttpPost("[action]")]
        public async Task<IActionResult> Login([FromBody] LoginDTO loginDTO)
        {
            var result = await _authService.LoginAsync(loginDTO);
            return result.IsSuccess ? Ok(result) : BadRequest(result);
        }
        [HttpPut("[action]")]
        [Authorize]
        public async Task<IActionResult> LogOut([FromQuery] Guid UserId)
        {            
            var result = await _authService.LogOutAsync(UserId.ToString());
            return result.IsSuccess ? Ok(result) : BadRequest(result);
        }

   
     
        [HttpPost("[action]")]
        public async Task<IActionResult> Register([FromBody] RegisterDTO registerDTO)
        {

            var result = await _authService.RegisterAsync(registerDTO);
            return result.IsSuccess ? Ok(result) : BadRequest(result);
        }
  
        [HttpPut("[action]")]
        public async Task<IActionResult> ChecekdConfirmedEmailToken([FromBody] ConfirmedEmailDTO confirmedEmailDTO)
        {
            if (string.IsNullOrEmpty(confirmedEmailDTO.Email) || string.IsNullOrEmpty(confirmedEmailDTO.token) ) return BadRequest();
            var result = await _authService.ChecekdConfirmedEmailTokenAsnyc(confirmedEmailDTO.Email, confirmedEmailDTO.token);
            return result.IsSuccess ? Ok(result) : BadRequest(result);
        }
        [HttpPut("[action]")]
        public async Task<IActionResult> SendEmailTokenForForgotPassword([FromQuery] string Email)
        {
            var result = await _authService.SendEmailTokenForForgotPasswordAsync(Email);
            return result.IsSuccess ? Ok(result) : BadRequest(result);
        }
        [HttpGet("[action]")]
        public async Task<IActionResult> CheckTokenForForgotPassword([FromQuery] string Email, [FromQuery] string Token)
        {
            var result = await _authService.CheckTokenForForgotPasswordAsync(Email, Token);
            return result.IsSuccess ? Ok(result) : BadRequest(result);
        }
        [HttpPut("[action]")]
        public async Task<IActionResult> ChangePasswordForTokenForgotPassword([FromQuery] string Email, [FromQuery] string Token, [FromQuery] string NewPassword)
        {
            var result = await _authService.ChangePasswordForTokenForgotPasswordAsync(Email, Token, NewPassword);
            return result.IsSuccess ? Ok(result) : BadRequest(result);
        }



    }
}
