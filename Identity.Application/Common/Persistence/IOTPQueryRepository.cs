using Identity.Domain.Identity;

namespace Identity.Application.Common.Persistence
{
    public interface IOTPQueryRepository
    {
        IEnumerable<OTP> GetUnusedOtpsByUserId(string userId);
        OTP? GetUnusedOtpByUserId(string userId);
    }
}
