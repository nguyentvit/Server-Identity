using FluentValidation;

namespace Identity.Application.Command.ConfirmEmail
{
    public class ConfirmEmailCommandValidator : AbstractValidator<ConfirmEmailCommand>
    {
        public ConfirmEmailCommandValidator() 
        {
            RuleFor(x => x.Otp).NotEmpty();
            RuleFor(x => x.hashedUserId).NotEmpty();
        }
    }
}
