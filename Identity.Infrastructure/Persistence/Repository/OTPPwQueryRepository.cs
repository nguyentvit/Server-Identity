using Dapper;
using Identity.Application.Common.Persistence;
using Identity.Application.Data;
using Identity.Domain.Identity;

namespace Identity.Infrastructure.Persistence.Repository
{
    public class OTPPwQueryRepository : IOTPPwQueryRepository
    {
        private readonly ISqlConnectionFactory _sqlConnectionFactory;
        public OTPPwQueryRepository(ISqlConnectionFactory sqlConnectionFactory)
        {
            _sqlConnectionFactory = sqlConnectionFactory;
        }

        public OTPPw? GetUnusedOtpByUserId(string userId)
        {
            using (var connection = _sqlConnectionFactory.GetOpenConnection())
            {
                var sql =
                    "select * from dbo.OTPPws " +
                    "where UserId = @UserId " +
                    "and " +
                    "IsUsed = 0 " +
                    "and " +
                    "ExpiryTime > GETUTCDATE()";

                var otp = connection.QueryFirstOrDefault<OTPPw>(sql, new { UserId = userId });
                return otp;
            }
        }

        public IEnumerable<OTPPw> GetUnusedOtpsByUserId(string userId)
        {
            using (var connection = _sqlConnectionFactory.GetOpenConnection())
            {
                var sql =
                    "select * from dbo.OTPPws " +
                    "where UserId = @userId " +
                    "and " +
                    "IsUsed = 0";
                var otps = connection.Query<OTPPw>(sql, new { UserId = userId });
                return otps;
            }
        }
    }
}
