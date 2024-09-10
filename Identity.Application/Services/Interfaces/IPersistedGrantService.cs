using Duende.IdentityServer.EntityFramework.Entities;

namespace Identity.Application.Services.Interfaces
{
    public interface IPersistedGrantService
    {
        Task<string> GetSubjectIdByKeyAsync(string key);
        Task<List<PersistedGrant>> GetAllGrantsBySubIdAsync(string SubId);

        Task RemoveAllGrantsBySubIdExceptItSelf(string SubId, string RefreshToken);
        Task RemoveGrantByRefreshTokenHashed(string refreshToken);


    }
}
