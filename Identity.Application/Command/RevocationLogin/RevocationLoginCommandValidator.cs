using FluentValidation;

namespace Identity.Application.Command.RevocationLogin
{
    public class RevocationLoginCommandValidator : AbstractValidator<RevocationLoginCommand>
    {
        public RevocationLoginCommandValidator() { }
    }
}
