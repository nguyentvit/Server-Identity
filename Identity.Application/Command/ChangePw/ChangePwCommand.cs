using ErrorOr;
using Identity.Application.Common.Results;
using MediatR;

namespace Identity.Application.Command.ChangePw
{
    public record ChangePwCommand(string Key, string Password, string ConfirmPassword, string UserId) : IRequest<ErrorOr<ChangePwResult>>;
}
