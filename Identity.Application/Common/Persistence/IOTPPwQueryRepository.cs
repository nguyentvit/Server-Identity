using Identity.Domain.Identity;

namespace Identity.Application.Common.Persistence
{
    public interface IOTPPwQueryRepository
    {
        IEnumerable<OTPPw> GetUnusedOtpsByUserId(string userId);
        OTPPw? GetUnusedOtpByUserId(string userId);
    }
}
