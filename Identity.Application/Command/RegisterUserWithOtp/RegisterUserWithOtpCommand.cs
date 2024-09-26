using ErrorOr;
using Identity.Application.Common.Results;
using MediatR;

namespace Identity.Application.Command.RegisterUserWithOtp
{
    public record RegisterUserWithOtpCommand(string Email, string PhoneNumber, string Name, string Password, string ConfirmPassword, string Otp) : IRequest<ErrorOr<RegisterUserWithOtpResult>>;
}
