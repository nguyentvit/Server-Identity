using Identity.Application.DomainEvents;
using Identity.Application.Services.Interfaces;
using MediatR;

namespace Identity.Application.DomainEventHandlers
{
    public class SendEmailDomainEventHandler : INotificationHandler<SendEmailDomainEvent>
    {
        private readonly IEmailSender _emailSender;
        public SendEmailDomainEventHandler(IEmailSender emailSender)
        {
            _emailSender = emailSender;
        }
        public async Task Handle(SendEmailDomainEvent notification, CancellationToken cancellationToken)
        {
            await Task.CompletedTask;

            await _emailSender.SendEmailAsync(notification.email, "Verify your OTP", $"Your OTP is {notification.otp}");
        }
    }
}
