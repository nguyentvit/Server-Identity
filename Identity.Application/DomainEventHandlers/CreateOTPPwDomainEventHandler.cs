using Identity.Application.Common.Persistence;
using Identity.Application.DomainEvents;
using Identity.Application.Services.Interfaces;
using Identity.Domain.Common.Models;
using Identity.Domain.Identity;
using MediatR;

namespace Identity.Application.DomainEventHandlers
{
    public class CreateOTPPwDomainEventHandler : INotificationHandler<CreateOTPPwDomainEvent>
    {
        private readonly IPublisher _mediator;
        private readonly IOTPPwCommandRepository _oTPPwCommandRepository;
        private readonly IOTPService _otpService;
        public CreateOTPPwDomainEventHandler(IMediator mediator, IOTPPwCommandRepository oTPPwCommandRepository, IOTPService otpService)
        {
            _mediator = mediator;
            _oTPPwCommandRepository = oTPPwCommandRepository;
            _otpService = otpService;
        }

        public async Task Handle(CreateOTPPwDomainEvent notification, CancellationToken cancellationToken)
        {
            var otp = _otpService.GenerateOTP();
            var hashOtp = _otpService.HashOTP(otp);

            OTPPw otpStore = new()
            {
                Code = hashOtp,
                ExpiryTime = DateTime.UtcNow.AddMinutes(15),
                IsUsed = false,
                UserId = notification.UserId
            };

            _oTPPwCommandRepository.Add(otpStore);

            await _mediator.Publish(new SendEmailDomainEvent(notification.Email, otp));
        }
    }
}
