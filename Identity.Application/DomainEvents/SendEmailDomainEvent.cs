using Identity.Domain.Model;

namespace Identity.Application.DomainEvents
{
    public record SendEmailDomainEvent(string email, string otp) : IDomainEvent;
}
