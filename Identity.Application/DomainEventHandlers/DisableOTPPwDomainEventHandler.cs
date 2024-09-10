using Identity.Application.Common.Persistence;
using Identity.Application.DomainEvents;
using MediatR;

namespace Identity.Application.DomainEventHandlers
{
    public class DisableOTPPwDomainEventHandler : INotificationHandler<DisableOTPPwDomainEvent>
    {
        private IOTPPwCommandRepository _commandRepository;
        private IOTPPwQueryRepository _queryRepository;
        public DisableOTPPwDomainEventHandler(IOTPPwCommandRepository commandRepository, IOTPPwQueryRepository queryRepository)
        {
            _commandRepository = commandRepository;
            _queryRepository = queryRepository;
        }

        public async Task Handle(DisableOTPPwDomainEvent notification, CancellationToken cancellationToken)
        {
            await Task.CompletedTask;

            var otp = _queryRepository.GetUnusedOtpByUserId(notification.UserId);

            if (otp != null)
            {
                otp.IsUsed = true;
                _commandRepository.Update(otp);
            }
        }
    }
}
