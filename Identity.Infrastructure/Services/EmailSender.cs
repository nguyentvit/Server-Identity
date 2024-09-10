using FluentEmail.Core;
using Identity.Application.Services.Interfaces;

namespace Identity.Infrastructure.Services
{
    public class EmailSender : IEmailSender
    {
        private readonly IFluentEmail _fluentEmail;
        public EmailSender(IFluentEmail fluentEmail)
        {
            _fluentEmail = fluentEmail;
        }
        public async Task SendEmailAsync(string email, string subject, string message)
        {
            await _fluentEmail
                    .To(email)
                    .Subject(subject)
                    .Body(message)
                    .SendAsync();
        }
    }
}
