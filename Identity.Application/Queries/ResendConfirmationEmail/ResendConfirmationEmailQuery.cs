using ErrorOr;
using Identity.Application.Common.Results;
using MediatR;
namespace Identity.Application.Queries.ResendConfirmationEmail
{
    public record ResendConfirmationEmailQuery(string Email) : IRequest<ErrorOr<RegisterResult>>;
}
