using Identity.Application.Common.Persistence;
using Identity.Application.DomainEvents;
using Identity.Application.Services.Interfaces;
using Identity.Domain.Common.Models;
using Identity.Domain.Identity;
using MediatR;

namespace Identity.Application.NotificationEventHandlers
{
    public class UserCreatedDomainEventHandler : INotificationHandler<UserCreatedDomainEvent>
    {
        private readonly IOTPCommandRepository _otpCommandRepository;
        private readonly IOTPService _otpService;
        private readonly IPublisher _mediator;
        public UserCreatedDomainEventHandler(IOTPCommandRepository otpCommandRepository, IOTPService otpService, IMediator mediator)
        {
            _otpCommandRepository = otpCommandRepository;
            _otpService = otpService;
            _mediator = mediator;
        }
        public async Task Handle(UserCreatedDomainEvent notification, CancellationToken cancellationToken)
        {
            await _mediator.Publish(new DisableOtpDomainEvent(notification.userId));

            var otp = _otpService.GenerateOTP();
            var hashOtp = _otpService.HashOTP(otp);

            OTP otpStore = new()
            {
                UserId = notification.userId,
                Code = hashOtp,
                ExpiryTime = DateTime.UtcNow.AddMinutes(15),
                IsUsed = false
            };

            _otpCommandRepository.Add(otpStore);

            await _mediator.Publish(new SendEmailDomainEvent(notification.email, otp));
        }
    }
}
