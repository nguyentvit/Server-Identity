using Dapper;
using Identity.Application.Common.Persistence;
using Identity.Application.Data;
using Identity.Domain.Identity;

namespace Identity.Infrastructure.Persistence.Repository
{
    public class ApplicationUserQueryRepository : IApplicationUserQueryRepository
    {
        private readonly ISqlConnectionFactory _sqlConnectionFactory;
        public ApplicationUserQueryRepository(ISqlConnectionFactory sqlConnectionFactory)
        {
            _sqlConnectionFactory = sqlConnectionFactory;
        }

        public ApplicationUser? GetUserByEmail(string email)
        {
            using (var connection = _sqlConnectionFactory.GetOpenConnection())
            {
                var sql = "SELECT *" +
                    "FROM [dbo].[AspNetUsers] " +
                    "WHERE [Email] = @Email";

                var user = connection.QueryFirstOrDefault<ApplicationUser>(sql, new { Email = email });
                return user;
            }
        }

        public ApplicationUser? GetUserByUserId(string userId)
        {
            using (var connection = _sqlConnectionFactory.GetOpenConnection())
            {
                var sql = "SELECT * " +
                    "FROM [dbo].[AspNetUsers] " +
                    "WHERE [Id] = @UserId";

                var user = connection.QueryFirstOrDefault<ApplicationUser>(sql, new { UserId = userId });
                return user;
            }
        }
    }
}
