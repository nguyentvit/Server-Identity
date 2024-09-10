using Identity.Application.Common.Persistence;
using Identity.Application.DomainEvents;
using MediatR;

namespace Identity.Application.DomainEventHandlers
{
    public class DisableOtpDomainEventHandler : INotificationHandler<DisableOtpDomainEvent>
    {
        private readonly IOTPQueryRepository _otpQueryRepository;
        private readonly IOTPCommandRepository _otpCommandRepository;
        public DisableOtpDomainEventHandler(IOTPQueryRepository otpQueryRepository, IOTPCommandRepository otpCommandRepository)
        {
            _otpQueryRepository = otpQueryRepository;
            _otpCommandRepository = otpCommandRepository;
        }

        public async Task Handle(DisableOtpDomainEvent notification, CancellationToken cancellationToken)
        {
            await Task.CompletedTask;

            var otps = _otpQueryRepository.GetUnusedOtpsByUserId(notification.userId);

            foreach (var otp in otps)
            {
                otp.IsUsed = true;
            }

            _otpCommandRepository.UpdateRange(otps);
        }
    }
}
