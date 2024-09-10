using Identity.Domain.Model;

namespace Identity.Application.DomainEvents
{
    public record ConfirmEmailDomainEvent(string userId) : IDomainEvent;
}
