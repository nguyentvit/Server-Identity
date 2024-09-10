using Identity.Application.Common.Persistence;
using Identity.Domain.Identity;

namespace Identity.Infrastructure.Persistence.Repository
{
    public class OTPCommandRepository : IOTPCommandRepository
    {
        private readonly IdentityDbContext _dbContext;
        public OTPCommandRepository(IdentityDbContext dbContext)
        {
            _dbContext=dbContext;
        }

        public void Add(OTP otp)
        {
            _dbContext.OTPs.Add(otp);
        }

        public void Update(OTP otp)
        {
            _dbContext.OTPs.Update(otp);
        }

        public void UpdateRange(IEnumerable<OTP> otps)
        {
            _dbContext.OTPs.UpdateRange(otps);
        }
    }
}
