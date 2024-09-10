using Identity.Domain.Common.Models;
using Microsoft.AspNetCore.Identity;

namespace Identity.Domain.Identity
{
    public class ApplicationUser : IdentityUser, AggregateRoot
    {
        public string Name { get; set; } = null!;
    }
}
