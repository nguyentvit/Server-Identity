using Identity.Application.Common.Persistence;
using Identity.Application.DomainEvents;
using MediatR;

namespace Identity.Application.DomainEventHandlers
{
    public class ForgetPasswordDomainEventHandler : INotificationHandler<ForgetPasswordDomainEvent>
    {
        private readonly IOTPPwQueryRepository _otppwQueryRepository;
        private readonly IOTPPwCommandRepository _otppwCommandRepository;
        private readonly IPublisher _mediator;
        public ForgetPasswordDomainEventHandler(
            IOTPPwQueryRepository otppwQueryRepository, 
            IOTPPwCommandRepository otppwCommandRepository, 
            IMediator mediator)
        {
            _otppwQueryRepository = otppwQueryRepository;
            _otppwCommandRepository = otppwCommandRepository;
            _mediator = mediator;
        }

        public async Task Handle(ForgetPasswordDomainEvent notification, CancellationToken cancellationToken)
        {

            var otppws = _otppwQueryRepository.GetUnusedOtpsByUserId(notification.UserId);

            foreach (var otppw in otppws)
            {
                otppw.IsUsed = true;
            }

            _otppwCommandRepository.UpdateRange(otppws);

            await _mediator.Publish(new CreateOTPPwDomainEvent(notification.UserId, notification.Email));
        }
    }
}
