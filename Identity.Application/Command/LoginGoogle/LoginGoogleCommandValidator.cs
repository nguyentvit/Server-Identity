using FluentValidation;

namespace Identity.Application.Command.LoginGoogle
{
    public class LoginGoogleCommandValidator : AbstractValidator<LoginGoogleCommand>
    {
        public LoginGoogleCommandValidator() { }
    }
}
