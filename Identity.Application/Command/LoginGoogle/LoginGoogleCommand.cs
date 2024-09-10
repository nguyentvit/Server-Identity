using ErrorOr;
using Identity.Application.Common.Results;
using MediatR;
using Microsoft.AspNetCore.Authentication;
namespace Identity.Application.Command.LoginGoogle
{
    public record LoginGoogleCommand(string AuthorizationCode) : IRequest<ErrorOr<LoginResult>>;
}
