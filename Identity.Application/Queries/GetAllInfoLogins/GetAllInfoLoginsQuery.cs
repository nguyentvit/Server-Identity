using ErrorOr;
using Identity.Application.Common.Results;
using MediatR;

namespace Identity.Application.Queries.GetAllInfoLogins
{
    public record GetAllInfoLoginsQuery(string userId) : IRequest<ErrorOr<GetAllInfoLoginsResult>>;
}
