using Identity.Application.Common.Persistence;
using Identity.Application.DomainEvents;
using Identity.Domain.Common.Models;
using MediatR;

namespace Identity.Application.DomainEventHandlers
{
    public class ConfirmEmailDomainEventHandler : INotificationHandler<ConfirmEmailDomainEvent>
    {
        private readonly IOTPQueryRepository _otpQueryRepository;
        private readonly IOTPCommandRepository _otpCommandRepository;
        public ConfirmEmailDomainEventHandler(IOTPQueryRepository otpQueryRepository, IOTPCommandRepository otpCommandRepository)
        {
            _otpQueryRepository = otpQueryRepository;
            _otpCommandRepository = otpCommandRepository;
        }

        public async Task Handle(ConfirmEmailDomainEvent notification, CancellationToken cancellationToken)
        {
            await Task.CompletedTask;

            var otp = _otpQueryRepository.GetUnusedOtpByUserId(notification.userId);

            if (otp != null)
            {
                otp.IsUsed = true;
                _otpCommandRepository.Update(otp);
            }
        }
    }
}
