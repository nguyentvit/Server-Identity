using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Entities;
using Identity.Infrastructure.Common.Interfaces;
namespace Identity.Infrastructure.Persistence.Repository
{
    public class PersistedGrantRepository : IPersistedGrantRepository
    {
        private readonly PersistedGrantDbContext _persistedGrantDbContext;
        public PersistedGrantRepository(PersistedGrantDbContext persistedGrantDbContext)
        {
            _persistedGrantDbContext = persistedGrantDbContext;
        }
        public async Task SaveAsync(PersistedGrant persistedGrant)
        {
            _persistedGrantDbContext.PersistedGrants.Add(persistedGrant);
            await _persistedGrantDbContext.SaveChangesAsync();
        }
        public async Task<PersistedGrant> GetByKeyAsync(string key)
        {
            return await _persistedGrantDbContext.PersistedGrants.FindAsync(key);
        }
    }
}
