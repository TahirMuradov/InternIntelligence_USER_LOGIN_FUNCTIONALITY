using InternIntelligence_USER_LOGIN_FUNCTIONALITY.Model.DTOs;
using InternIntelligence_USER_LOGIN_FUNCTIONALITY.Model;
using InternIntelligence_USER_LOGIN_FUNCTIONALITY.Security;
using Core.Utilites.Results.Abstract;
using Entites.DTOs;



namespace Bussines.Abstract
{
    public interface IAuthService
    {

   
        Task<IResult> ChecekdConfirmedEmailTokenAsnyc(string email, string token);
      
        Task<IResult> RegisterAsync(RegisterDTO registerDTO);

        Task<IResult> SendEmailTokenForForgotPasswordAsync(string Email);
        Task<IResult> CheckTokenForForgotPasswordAsync(string Email, string token);
        Task<IResult> ChangePasswordForTokenForgotPasswordAsync(string Email, string token, string NewPassword);
  
        Task<IDataResult<string>> UpdateRefreshTokenAsnyc(string refreshToken, User user);

        Task<IDataResult<Token>> LoginAsync(LoginDTO loginDTO);
        Task<IResult> LogOutAsync(string userId);
        Task<IDataResult<Token>> RefreshTokenLoginAsync(string refreshToken);
    }
}
