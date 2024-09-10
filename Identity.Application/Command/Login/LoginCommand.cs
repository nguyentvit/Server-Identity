using ErrorOr;
using MediatR;
using Identity.Application.Common.Results;

namespace Identity.Application.Command.Login
{
    public record LoginCommand(string Email, string Password) : IRequest<ErrorOr<LoginResult>>;
}
