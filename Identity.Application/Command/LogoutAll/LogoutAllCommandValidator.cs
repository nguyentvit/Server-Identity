using FluentValidation;

namespace Identity.Application.Command.LogoutAll
{
    public class LogoutAllCommandValidator : AbstractValidator<LogoutAllCommand>
    {
        public LogoutAllCommandValidator() { }
    }
}
