using ErrorOr;
using Identity.Application.Common.Results;
using MediatR;

namespace Identity.Application.Command.RefreshTokenGoogle
{
    public record RefreshTokenGoogleCommand(string RefreshToken) : IRequest<ErrorOr<RefreshTokenResult>>;
}
