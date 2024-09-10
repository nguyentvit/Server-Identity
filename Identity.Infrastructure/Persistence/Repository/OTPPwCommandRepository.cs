using Identity.Application.Common.Persistence;
using Identity.Domain.Identity;

namespace Identity.Infrastructure.Persistence.Repository
{
    public class OTPPwCommandRepository : IOTPPwCommandRepository
    {
        private readonly IdentityDbContext _dbContext;
        public OTPPwCommandRepository(IdentityDbContext dbContext)
        {
            _dbContext = dbContext;
        }
        public void Add(OTPPw OTPPw)
        {
            _dbContext.OTPPws.Add(OTPPw);
        }

        public void Update(OTPPw OTPPw)
        {
            _dbContext.OTPPws.Update(OTPPw);
        }

        public void UpdateRange(IEnumerable<OTPPw> oTPPws)
        {
            _dbContext.OTPPws.UpdateRange(oTPPws);
        }
    }
}
