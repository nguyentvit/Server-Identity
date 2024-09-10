using FluentValidation;

namespace Identity.Application.Command.RefreshTokenGoogle
{
    public class RefreshTokenGoogleCommandValidator : AbstractValidator<RefreshTokenGoogleCommand>
    {
        public RefreshTokenGoogleCommandValidator() { }
    }
}
