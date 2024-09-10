using Identity.Domain.Model;
using MediatR;

namespace Identity.Application.DomainEvents
{
    public record UserCreatedDomainEvent(string userId, string email) : IDomainEvent;
}
