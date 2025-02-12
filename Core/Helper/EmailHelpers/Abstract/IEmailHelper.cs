using Core.Utilites.Results.Abstract;

namespace InternIntelligence_USER_LOGIN_FUNCTIONALITY.Helper.EmailHelpers.Abstract
{
    public interface IEmailHelper
    {
        public Task<IResult> SendEmailAsync(string userEmail, string confirmationLink, string UserName);
    }
}
