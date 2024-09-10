using Identity.Domain.Common.Models;
using Microsoft.EntityFrameworkCore;

namespace Identity.Infrastructure.Persistence
{
    public class UnitOfWork : IUnitOfWork
    {
        private readonly IdentityDbContext _dbContext;
        public UnitOfWork(IdentityDbContext dbContext)
        {
            _dbContext = dbContext;
        }
        public Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
        {
            return _dbContext.SaveChangesAsync(cancellationToken);
        }
    }
}
