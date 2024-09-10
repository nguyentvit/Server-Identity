using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Entities;
using Identity.Application.Services.Interfaces;
using Microsoft.EntityFrameworkCore;
using System;

namespace Identity.Infrastructure.Services
{
    public class PersistedGrantService : IPersistedGrantService
    {
        private readonly PersistedGrantDbContext _persistedGrantDbContext;
        private readonly IRefreshTokenHasher _refreshTokenHasher;

        public PersistedGrantService(PersistedGrantDbContext persistedGrantDbContext, IRefreshTokenHasher refreshTokenHasher)
        {
            _persistedGrantDbContext = persistedGrantDbContext;
            _refreshTokenHasher = refreshTokenHasher;
        }

        public async Task<List<PersistedGrant>> GetAllGrantsBySubIdAsync(string SubId)
        {
            var currentTime = DateTime.UtcNow;
            return await _persistedGrantDbContext.PersistedGrants.Where(pg => pg.SubjectId == SubId && pg.Expiration > currentTime).ToListAsync();
        }
        
        public async Task RemoveAllGrantsBySubIdExceptItSelf(string SubId, string RefreshToken)
        {
            var key = _refreshTokenHasher.sha256_hash(RefreshToken);

            var grantsToRemove = await _persistedGrantDbContext.PersistedGrants
                 .Where(pg => pg.SubjectId == SubId && pg.Key != key)
                 .ToListAsync();

            if (grantsToRemove.Any())
            {
                _persistedGrantDbContext.PersistedGrants.RemoveRange(grantsToRemove);
                await _persistedGrantDbContext.SaveChangesAsync();
            }

        }

        public Task<string> GetSubjectIdByKeyAsync(string key)
        {
            throw new NotImplementedException();
        }

        public async Task RemoveGrantByRefreshTokenHashed(string refreshToken)
        {
            var grantToRemove = await _persistedGrantDbContext.PersistedGrants.Where(pg => pg.Key == refreshToken).FirstOrDefaultAsync();

            if ( grantToRemove != null )
            {
                _persistedGrantDbContext.PersistedGrants.Remove(grantToRemove);
                await _persistedGrantDbContext.SaveChangesAsync();
            }
        }
    }
}
