using ErrorOr;
using Identity.Application.Common.Results;
using MediatR;

namespace Identity.Application.Command.Logout
{
    public record LogoutCommand(string AccessToken, string RefreshToken) : IRequest<ErrorOr<LogoutResult>>;
}
