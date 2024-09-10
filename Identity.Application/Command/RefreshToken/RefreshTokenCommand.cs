using ErrorOr;
using Identity.Application.Common.Results;
using MediatR;

namespace Identity.Application.Command.RefreshToken
{
    public record RefreshTokenCommand(string RefreshToken) : IRequest<ErrorOr<RefreshTokenResult>>;
}
