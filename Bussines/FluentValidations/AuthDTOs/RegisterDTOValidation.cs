using FluentValidation;
using InternIntelligence_USER_LOGIN_FUNCTIONALITY.Model.DTOs;

namespace InternIntelligence_USER_LOGIN_FUNCTIONALITY.FluentValidations.AuthDTOs
{
    public class RegisterDTOValidation: AbstractValidator<RegisterDTO>
    {
        public RegisterDTOValidation()
        {
            RuleFor(x => x.Firstname)
                 .NotEmpty().WithMessage("Firstname cannot be empty")
                 .MaximumLength(50).WithMessage("Firstname cannot exceed 50 characters");

            RuleFor(x => x.Lastname)
                .NotEmpty().WithMessage("Lastname cannot be empty")
                .MaximumLength(50).WithMessage("Lastname cannot exceed 50 characters");

            RuleFor(x => x.Email)
                .NotEmpty().WithMessage("Email cannot be empty")
                .EmailAddress().WithMessage("Invalid email format");

            RuleFor(x => x.PhoneNumber)
                .NotEmpty().WithMessage("Phone number cannot be empty")
                               .Matches(@"^(?:\+994-?(?:\d{2}-?\d{3}-?\d{2}-?\d{2}|\d{2}-?\d{3}-?\d{2}-?\d{2})|(\d{3}-?\d{3}-?\d{2}-?\d{2}|\d{3}-?\d{3}-?\d{2}-?\d{2}-?))$")
.WithMessage("Phone number is invalid format!");

            RuleFor(x => x.Username)
                .NotEmpty().WithMessage("Username cannot be empty")
                .MinimumLength(4).WithMessage("Username must be at least 4 characters long");

            RuleFor(x => x.Password)
                .NotEmpty().WithMessage("Password cannot be empty")
                .MinimumLength(6).WithMessage("Password must be at least 6 characters long");

            RuleFor(x => x.ConfirmPassword)
                .NotEmpty().WithMessage("Confirm password cannot be empty")
                .Equal(x => x.Password).WithMessage("Passwords do not match");
        }
    }
}
