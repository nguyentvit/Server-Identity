using FluentValidation;

namespace Identity.Application.Command.VerifyOtpEmail
{
    public class VerifyOtpEmailCommandValidator : AbstractValidator<VerifyOtpEmailCommand>
    {
        public VerifyOtpEmailCommandValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty()
                .EmailAddress()
                .WithMessage("Invalid email format");

            RuleFor(x => x.Otp)
                .NotEmpty()
                .Length(6)
                .WithMessage("Lenght otp is 6");
        }
    }
}
