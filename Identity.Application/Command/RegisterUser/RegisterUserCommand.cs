using ErrorOr;
using Identity.Application.Common.Results;
using MediatR;

namespace Identity.Application.Command.RegisterUser
{
    public record RegisterUserCommand(string Email, string PhoneNumber, string Name, string Password, string ConfirmPassword) : IRequest<ErrorOr<RegisterResult>>;
}
