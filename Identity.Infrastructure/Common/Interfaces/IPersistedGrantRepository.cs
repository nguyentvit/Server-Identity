using Duende.IdentityServer.EntityFramework.Entities;

namespace Identity.Infrastructure.Common.Interfaces
{
    public interface IPersistedGrantRepository
    {
        Task SaveAsync(PersistedGrant persistedGrant);
        Task<PersistedGrant> GetByKeyAsync(string key);
    }
}

