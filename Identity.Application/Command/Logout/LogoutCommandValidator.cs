using FluentValidation;

namespace Identity.Application.Command.Logout
{
    public class LogoutCommandValidator : AbstractValidator<LogoutCommand>
    {
        public LogoutCommandValidator() { }
    }
}
