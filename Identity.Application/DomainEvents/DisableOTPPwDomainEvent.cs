using Identity.Domain.Model;

namespace Identity.Application.DomainEvents
{
    public record DisableOTPPwDomainEvent(string UserId) : IDomainEvent;
}
