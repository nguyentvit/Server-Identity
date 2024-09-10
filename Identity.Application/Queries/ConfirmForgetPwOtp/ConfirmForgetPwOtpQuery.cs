using ErrorOr;
using Identity.Application.Common.Results;
using MediatR;

namespace Identity.Application.Queries.ConfirmForgetPwOtp
{
    public record ConfirmForgetPwOtpQuery(string HashedUserId, string Otp) : IRequest<ErrorOr<ForgetPasswordResult>>;
}
