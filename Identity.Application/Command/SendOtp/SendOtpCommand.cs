using ErrorOr;
using Identity.Application.Common.Results;
using MediatR;

namespace Identity.Application.Command.SendOtp
{
    public record SendOtpCommand(string Email) : IRequest<ErrorOr<SendOtpResult>>;
}
