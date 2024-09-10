using ErrorOr;
using Identity.Application.Common.Results;
using MediatR;

namespace Identity.Application.Command.RevocationLogin
{
    public record RevocationLoginCommand(string UserId, string RefreshToken, string AccessToken) : IRequest<ErrorOr<RevocationLoginResult>>;
}
