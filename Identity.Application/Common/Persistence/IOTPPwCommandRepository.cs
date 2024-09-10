using Identity.Domain.Identity;

namespace Identity.Application.Common.Persistence
{
    public interface IOTPPwCommandRepository
    {
        void Add(OTPPw OTPPw);
        void UpdateRange(IEnumerable<OTPPw> oTPPws);
        void Update(OTPPw OTPPw);
    }
}
