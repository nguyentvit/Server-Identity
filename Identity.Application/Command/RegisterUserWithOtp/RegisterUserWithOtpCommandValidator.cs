using FluentValidation;

namespace Identity.Application.Command.RegisterUserWithOtp
{
    public class RegisterUserWithOtpCommandValidator : AbstractValidator<RegisterUserWithOtpCommand>
    {
        public RegisterUserWithOtpCommandValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty()
                .EmailAddress().WithMessage("Invalid email format");

            RuleFor(x => x.Password)
                .NotEmpty()
                .MinimumLength(6).WithMessage("Password must be at least 6 characters long")
                .Matches("[A-Z]").WithMessage("Password must contain at least one uppercase letter")
                .Matches("[a-z]").WithMessage("Password must contain at least one lowercase letter")
                .Matches("[0-9]").WithMessage("Password must contain at least one number")
                .Matches("[^a-zA-Z0-9]").WithMessage("Password must contain at least one special character");

            RuleFor(x => x.ConfirmPassword)
                .Equal(x => x.Password).WithMessage("Passwords do not match");

            RuleFor(x => x.PhoneNumber)
                .NotEmpty()
                .Matches(@"^\+?[0-9]\d{1,14}$").WithMessage("Invalid phone number format");

            RuleFor(x => x.Otp)
                .NotEmpty()
                .Length(6)
                .WithMessage("Length Otp is 6");
        }
    }
}
