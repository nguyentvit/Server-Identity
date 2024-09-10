using ErrorOr;
using Identity.Application.Common.Results;
using MediatR;

namespace Identity.Application.Command.ConfirmEmail
{
    public record ConfirmEmailCommand(string hashedUserId, string Otp) : IRequest<ErrorOr<ConfirmEmailResult>>;
}
