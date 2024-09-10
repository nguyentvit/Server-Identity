using FluentValidation;

namespace Identity.Application.Queries.ForgetPassword
{
    public class ForgetPasswordQueryValidator : AbstractValidator<ForgetPasswordQuery>
    {
        public ForgetPasswordQueryValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty()
                .EmailAddress().WithMessage("Invalid Email Format");
        }
    }
}
