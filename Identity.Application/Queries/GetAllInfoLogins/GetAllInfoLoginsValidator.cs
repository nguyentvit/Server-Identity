using FluentValidation;
using Identity.Application.Common.Results;

namespace Identity.Application.Queries.GetAllInfoLogins
{
    public class GetAllInfoLoginsValidator : AbstractValidator<GetAllInfoLoginsResult>
    {
        public GetAllInfoLoginsValidator() { }
    }
}
