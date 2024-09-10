using ErrorOr;
using Identity.Application.Common.Persistence;
using Identity.Application.Common.Results;
using Identity.Application.DomainEvents;
using Identity.Application.Services.Interfaces;
using Identity.Domain.Common.Errors;
using Identity.Domain.Common.Models;
using MediatR;

namespace Identity.Application.Queries.ResendConfirmationEmail
{
    public class ResendConfirmationEmailQueryHandler : IRequestHandler<ResendConfirmationEmailQuery, ErrorOr<RegisterResult>>
    {
        private readonly ITokenProvider _tokenProvider;
        private IPublisher _mediator;
        private readonly IUnitOfWork _unitOfWork;
        private readonly IApplicationUserQueryRepository _userQueryRepository;
        public ResendConfirmationEmailQueryHandler(ITokenProvider tokenProvider, IMediator mediator, IUnitOfWork unitOfWork, IApplicationUserQueryRepository userQueryRepository)
        {
            _tokenProvider = tokenProvider;
            _mediator = mediator;
            _unitOfWork = unitOfWork;
            _userQueryRepository = userQueryRepository;
        }

        public async Task<ErrorOr<RegisterResult>> Handle(ResendConfirmationEmailQuery request, CancellationToken cancellationToken)
        {

            var user = _userQueryRepository.GetUserByEmail(request.Email);

            if (user == null)
            {
                return Errors.User.NotFoundUser;
            }

            if (user.EmailConfirmed)
            {
                return Errors.User.EmailConfirmed;
            }

            await _mediator.Publish(new UserCreatedDomainEvent(user.Id, user.Email));
            int count = await _unitOfWork.SaveChangesAsync();

            var key = _tokenProvider.GenerateEmailConfirmationToken(user);
            var confirmUrl = $"https://localhost:7100/api/v1/Account/confirmEmail/?key={key}";

            RegisterDataResult data = new(user.Email, user.Id, user.UserName, confirmUrl);
            RegisterResult registerResult = new(true, "Registration successful. Please check your email to confirm your account.", data);

            return registerResult;

        }
    }
}
