using Dapper;
using Identity.Application.Common.Persistence;
using Identity.Application.Data;
using Identity.Domain.Identity;

namespace Identity.Infrastructure.Persistence.Repository
{
    public class OTPQueryRepository : IOTPQueryRepository
    {
        private readonly ISqlConnectionFactory _sqlConnectionFactory;
        public OTPQueryRepository(ISqlConnectionFactory sqlConnectionFactory)
        {
            _sqlConnectionFactory = sqlConnectionFactory;
        }

        public OTP? GetUnusedOtpByUserId(string userId)
        {
            using (var connection = _sqlConnectionFactory.GetOpenConnection())
            {
                var sql = 
                    "select * from dbo.OTPs " +
                    "where UserId = @UserId " +
                    "and " +
                    "IsUsed = 0 " +
                    "and " +
                    "ExpiryTime > GETUTCDATE()";

                var otp = connection.QueryFirstOrDefault<OTP>(sql, new { UserId = userId });
                return otp;
            }
        }

        public IEnumerable<OTP> GetUnusedOtpsByUserId(string userId)
        {
            using (var connection = _sqlConnectionFactory.GetOpenConnection())
            {
                var sql = 
                    "select * from dbo.OTPs " +
                    "where UserId = @userId " +
                    "and " +
                    "IsUsed = 0";
                var otps = connection.Query<OTP>(sql, new { UserId = userId });
                return otps;
            }
        }
    }
}
