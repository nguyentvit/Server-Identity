using Identity.Domain.Identity;

namespace Identity.Application.Common.Persistence
{
    public interface IOTPCommandRepository
    {
        void Add(OTP otp);
        void UpdateRange(IEnumerable<OTP> otps);
        void Update(OTP otp);
    }
}
