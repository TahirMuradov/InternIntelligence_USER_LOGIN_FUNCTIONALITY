using Entites.DTOs;
using FluentValidation;
using System.Globalization;

namespace Bussines.FluentValidations.AuthDTOs
{
    public class LoginDTOValidation: AbstractValidator<LoginDTO>
    {
        public LoginDTOValidation()
        {
            
            RuleFor(x => x.Email)
                .NotEmpty().WithMessage("Email is required.")
                .EmailAddress().WithMessage("Invalid email format.");

            RuleFor(x => x.Password)
                .NotEmpty().WithMessage("Password is required.");

        }
    }
}
