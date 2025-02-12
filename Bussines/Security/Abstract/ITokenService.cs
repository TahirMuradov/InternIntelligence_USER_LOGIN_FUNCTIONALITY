using InternIntelligence_USER_LOGIN_FUNCTIONALITY.Model;

namespace InternIntelligence_USER_LOGIN_FUNCTIONALITY.Security.Abstract
{
    public interface ITokenService
    {
        Task<Token> CreateAccessTokenAsync(User User, List<string> roles);
        string CreateRefreshToken();
    }
}
