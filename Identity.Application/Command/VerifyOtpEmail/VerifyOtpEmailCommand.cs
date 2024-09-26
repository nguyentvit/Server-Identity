using ErrorOr;
using Identity.Application.Common.Results;
using MediatR;

namespace Identity.Application.Command.VerifyOtpEmail
{
    public record VerifyOtpEmailCommand(string Email, string Otp) : IRequest<ErrorOr<VerifyOtpEmailResult>>;
}
