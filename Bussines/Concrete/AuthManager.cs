using Bussines.Abstract;
using Bussines.FluentValidations.AuthDTOs;
using Core.Helper;
using Core.Utilites.Results.Abstract;
using Core.Utilites.Results.Concrete.ErrorResults;
using Core.Utilites.Results.Concrete.SuccessResults;
using Entites.DTOs;
using InternIntelligence_USER_LOGIN_FUNCTIONALITY.FluentValidations.AuthDTOs;
using InternIntelligence_USER_LOGIN_FUNCTIONALITY.Helper.EmailHelpers.Abstract;
using InternIntelligence_USER_LOGIN_FUNCTIONALITY.Model;
using InternIntelligence_USER_LOGIN_FUNCTIONALITY.Model.DTOs;
using InternIntelligence_USER_LOGIN_FUNCTIONALITY.Security;
using InternIntelligence_USER_LOGIN_FUNCTIONALITY.Security.Abstract;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System.Net;
using System.Web;

namespace Bussines.Concrete
{
    public class AuthManager : IAuthService
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly RoleManager<Role> _roleManager;
        private readonly ITokenService _tokenService;
        private readonly IEmailHelper _emailHelper;
        private readonly IConfiguration _configuration;



        public AuthManager(UserManager<User> userManager, SignInManager<User> signInManager, RoleManager<Role> roleManager, ITokenService tokenService, IEmailHelper emailHelper, IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _tokenService = tokenService;
            _emailHelper = emailHelper;
            _configuration = configuration;
        }

        public async Task<IResult> ChangePasswordForTokenForgotPasswordAsync(string Email, string token, string NewPassword)
        {
            if (string.IsNullOrEmpty(Email) || string.IsNullOrEmpty(token) || string.IsNullOrEmpty(NewPassword))
                return new ErrorResult(HttpStatusCode.BadRequest);
            Email = HttpUtility.UrlDecode(Email);
            var user = await _userManager.FindByEmailAsync(Email);
            if (user is null)
                return new ErrorResult(HttpStatusCode.NotFound);

            token = HttpUtility.UrlDecode(token);
            NewPassword = HttpUtility.UrlDecode(NewPassword);
            var tokenResult = await _userManager.ResetPasswordAsync(user, token, NewPassword);
            if (tokenResult.Succeeded)
                return new SuccessResult(HttpStatusCode.OK);
            return new ErrorResult(messages: tokenResult.Errors.Select(x => x.Description).ToList(), HttpStatusCode.BadRequest);
        }

        public async Task<IResult> ChecekdConfirmedEmailTokenAsnyc(string email, string token)
        {
            var checekedEmail = await _userManager.FindByEmailAsync(email);
            if (checekedEmail is null) return new ErrorResult(message: "User  not found!", HttpStatusCode.NotFound);

            if (checekedEmail.EmailConfirmed)
                return new ErrorResult(HttpStatusCode.BadRequest);
            IdentityResult checekedResult = await _userManager.ConfirmEmailAsync(checekedEmail, token);
            if (checekedResult.Succeeded)

                return new SuccessResult(messages: checekedResult.Errors.Select(x => x.Description).ToList(), HttpStatusCode.OK);

            else
                return new ErrorResult(messages: checekedResult.Errors.Select(x => x.Description).ToList(), HttpStatusCode.BadRequest);


        }

        public async Task<IResult> CheckTokenForForgotPasswordAsync(string Email, string token)
        {
            if (string.IsNullOrEmpty(Email) || string.IsNullOrEmpty(token)) return new ErrorResult(HttpStatusCode.BadRequest);

            Email = HttpUtility.UrlDecode(Email);
            token = HttpUtility.UrlDecode(token);
            var user = await _userManager.FindByEmailAsync(Email);
            if (user is null)
                return new ErrorResult(HttpStatusCode.NotFound);
            bool tokenResult = await _userManager.VerifyUserTokenAsync(
   user: user,
   tokenProvider: _userManager.Options.Tokens.PasswordResetTokenProvider,
   purpose: UserManager<User>.ResetPasswordTokenPurpose,
   token: token
                  );

            if (tokenResult) return new SuccessResult(HttpStatusCode.OK);
            return new ErrorResult(HttpStatusCode.BadRequest);
        }

        public async Task<IDataResult<Token>> LoginAsync(LoginDTO loginDTO)
        {
            LoginDTOValidation validationRules = new LoginDTOValidation();
            var ValidationResult = await validationRules.ValidateAsync(loginDTO);
            if (!ValidationResult.IsValid)
                return new ErrorDataResult<Token>(messages: ValidationResult.Errors.Select(x => x.ErrorMessage).ToList(), HttpStatusCode.BadRequest);

            var user = await _userManager.FindByEmailAsync(loginDTO.Email);

            if (user is null)
                return new ErrorDataResult<Token>("User not found", HttpStatusCode.NotFound);


            var result = await _signInManager.CheckPasswordSignInAsync(user, loginDTO.Password, false);
            var roles = await _userManager.GetRolesAsync(user);

            if (result.Succeeded)
            {
                Token token = await _tokenService.CreateAccessTokenAsync(user, roles.ToList());
                var response = await UpdateRefreshTokenAsnyc(refreshToken: token.RefreshToken, user);
                if (response.IsSuccess)
                    return new SuccessDataResult<Token>(response: token, statusCode: HttpStatusCode.OK, message: response.Message);
                else
                    return new ErrorDataResult<Token>(statusCode: HttpStatusCode.BadRequest, message: response.Message);
            }
            else
                return new ErrorDataResult<Token>(statusCode: HttpStatusCode.BadRequest, message: "User not found");
        }

        public async Task<IResult> LogOutAsync(string userId)
        {
            if (string.IsNullOrEmpty(userId)) return new ErrorResult(statusCode: HttpStatusCode.NotFound, message: "User  not found!");

            var findUser = await _userManager.FindByIdAsync(userId);
            if (findUser == null)
                return new ErrorResult(statusCode: HttpStatusCode.NotFound, message: "User  not found!");


            findUser.RefreshToken = null;
            findUser.RefreshTokenExpiredDate = null;
            var result = await _userManager.UpdateAsync(findUser);
            await _signInManager.SignOutAsync();
            if (result.Succeeded)
            {
                return new SuccessResult(statusCode: HttpStatusCode.OK);
            }
            else
            {

                return new ErrorDataResult<Token>(statusCode: HttpStatusCode.BadRequest, messages: result.Errors.Select(x => x.Description).ToList());
            }
        }

        public async Task<IDataResult<Token>> RefreshTokenLoginAsync(string refreshToken)
        {
            var user = await _userManager.Users.FirstOrDefaultAsync(x => x.RefreshToken == refreshToken);
            if (user is null) return new ErrorDataResult<Token>(message: "User not found!", HttpStatusCode.NotFound);
            var roles = await _userManager.GetRolesAsync(user);

            if (user != null && user?.RefreshTokenExpiredDate > DateTime.UtcNow.AddHours(4))
            {
                Token token = await _tokenService.CreateAccessTokenAsync(user, roles.ToList());
                token.RefreshToken = refreshToken;
                return new SuccessDataResult<Token>(response: token, statusCode: HttpStatusCode.OK);
            }
            else
                return new ErrorDataResult<Token>(statusCode: HttpStatusCode.BadRequest, message: "User  not found!");
        }

        public async Task<IResult> RegisterAsync(RegisterDTO registerDTO)
        {
            RegisterDTOValidation validationRules = new RegisterDTOValidation();
            var validationResult = await validationRules.ValidateAsync(registerDTO);
            if (!validationResult.IsValid) return new ErrorResult(messages: validationResult.Errors.Select(x => x.ErrorMessage).ToList(), HttpStatusCode.BadRequest);
            var checkEmail = await _userManager.Users.FirstOrDefaultAsync(x => x.Email == registerDTO.Email);
            var checkUserName = await _userManager.FindByNameAsync(registerDTO.Username);

            if (checkEmail != null)
                return new ErrorResult(statusCode: HttpStatusCode.BadRequest, message: "Email is already in use!");

            if (checkUserName != null)
                return new ErrorResult(statusCode: HttpStatusCode.BadRequest, message: "UserName is already in use!");

            User newUser = new()
            {
                FirstName = registerDTO.Firstname,
                LastName = registerDTO.Lastname,
                Email = registerDTO.Email,
                UserName = registerDTO.Username,
                PhoneNumber = registerDTO.PhoneNumber,



            };

                string a = ConfigurationHelper.config.GetSection("Domain:Api").Get<string>();
            IdentityResult identityResult = await _userManager.CreateAsync(newUser, registerDTO.Password);

            if (identityResult.Succeeded)
            {

                string token = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);

                string confimationLink = $"{ConfigurationHelper.config.GetSection("Domain:Front").Get<string>()}/auth/emailconfirmed/{HttpUtility.UrlEncode(newUser.Email)}/{HttpUtility.UrlEncode(token)}";
                var resultEmail = await _emailHelper.SendEmailAsync(newUser.Email, confimationLink, newUser.FirstName + newUser.LastName);
                if (!resultEmail.IsSuccess)
                {
                    await _userManager.DeleteAsync(await _userManager.FindByEmailAsync(newUser.Email));
                    return new ErrorResult(message: "Verification Link could not be sent! Try registering again.", HttpStatusCode.BadRequest);
                }
                return new SuccessResult(message: "Registration successful!", statusCode: HttpStatusCode.Created);
            }
            else
            {

                return new ErrorResult(messages: identityResult.Errors.Select(x => x.Description).ToList(), HttpStatusCode.BadRequest);
            }
        }

        public async Task<IResult> SendEmailTokenForForgotPasswordAsync(string Email)
        {
            if (string.IsNullOrEmpty(Email)) return new ErrorResult(HttpStatusCode.BadRequest);
            var user = await _userManager.FindByEmailAsync(Email);
            if (user is null)
                return new ErrorResult(HttpStatusCode.NotFound);
            string token = await _userManager.GeneratePasswordResetTokenAsync(user);

            var url = _configuration["Domain:Front"] + $"/auth/forgotpassword/confirmation/{HttpUtility.UrlEncode(Email)}/{HttpUtility.UrlEncode(token)}";
            var emailResult = await _emailHelper.SendEmailAsync(user.Email, url, user.FirstName + user.LastName);


            if (emailResult.IsSuccess)

                return new SuccessResult(HttpStatusCode.OK);

            return new ErrorResult(HttpStatusCode.BadRequest);
        }

        public async Task<IDataResult<string>> UpdateRefreshTokenAsnyc(string refreshToken, User user)
        {

            if (user is not null)
            {
                user.RefreshToken = refreshToken;
                user.RefreshTokenExpiredDate = DateTime.UtcNow.AddMonths(1);

                IdentityResult identityResult = await _userManager.UpdateAsync(user);

                if (identityResult.Succeeded)
                    return new SuccessDataResult<string>(statusCode: HttpStatusCode.OK, response: refreshToken);
                else
                    return new ErrorDataResult<string>(messages: identityResult.Errors.Select(x => x.Description).ToList(), HttpStatusCode.BadRequest);

            }
            else
                return new ErrorDataResult<string>("User not found!", HttpStatusCode.NotFound);
        }
    }
}
