using ErrorOr;
using Identity.Application.Common.Results;
using MediatR;

namespace Identity.Application.Queries.ForgetPassword
{
    public record ForgetPasswordQuery(string Email) : IRequest<ErrorOr<ForgetPasswordResult>>;
}
