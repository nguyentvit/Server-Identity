using Dapper;
using ErrorOr;
using Identity.Application.Common.Persistence;
using Identity.Application.Common.Results;
using Identity.Application.DomainEvents;
using Identity.Application.Services.Interfaces;
using Identity.Domain.Common.Errors;
using Identity.Domain.Common.Models;
using MediatR;

namespace Identity.Application.Queries.ForgetPassword
{
    public class ForgetPasswordQueryHandler : IRequestHandler<ForgetPasswordQuery, ErrorOr<ForgetPasswordResult>>
    {
        private readonly ITokenProvider _tokenProvider;
        private IPublisher _mediator;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IApplicationUserQueryRepository _applicationUserQueryRepository; 
        public ForgetPasswordQueryHandler(
            ITokenProvider tokenProvider, 
            IMediator mediator, 
            IUnitOfWork unitOfWork,
            IApplicationUserQueryRepository applicationUserQueryRepository
            )
        {
            _tokenProvider = tokenProvider;
            _mediator = mediator;
            _unitOfWork = unitOfWork;
            _applicationUserQueryRepository = applicationUserQueryRepository;
        }

        public async Task<ErrorOr<ForgetPasswordResult>> Handle(ForgetPasswordQuery request, CancellationToken cancellationToken)
        {

            var user = _applicationUserQueryRepository.GetUserByEmail(request.Email);

            if (user == null)
            {
                return Errors.User.NotFoundUser;
            }

            if (!user.EmailConfirmed)
            {
                return Errors.User.EmailUnConfirm;
            }

            await _mediator.Publish(new ForgetPasswordDomainEvent(user.Id, user.Email));
            int count = await _unitOfWork.SaveChangesAsync();

            var key = _tokenProvider.GenerateEmailConfirmationToken(user);
            var forgetUrl = $"https://localhost:7100/api/v1/Account/confirm-forget-pw/?key={key}";

            var message = "A link to reset your password has been sent to your email.";

            ForgetPasswordResult result = new ForgetPasswordResult("success", message, user.Email, forgetUrl);

            return result;
        }
    }
}
