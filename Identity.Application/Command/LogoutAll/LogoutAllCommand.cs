using ErrorOr;
using Identity.Application.Common.Results;
using MediatR;

namespace Identity.Application.Command.LogoutAll
{
    public record LogoutAllCommand(string AccessToken, string UserId) : IRequest<ErrorOr<LogoutResult>>;
}
