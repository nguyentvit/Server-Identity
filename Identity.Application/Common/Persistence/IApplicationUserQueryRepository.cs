using Identity.Domain.Identity;

namespace Identity.Application.Common.Persistence
{
    public interface IApplicationUserQueryRepository
    {
        ApplicationUser? GetUserByUserId(string userId);
        ApplicationUser? GetUserByEmail(string email);
    }
}
