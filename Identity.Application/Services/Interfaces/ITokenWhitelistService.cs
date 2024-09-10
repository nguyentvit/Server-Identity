using Identity.Application.Common.Contracts;

namespace Identity.Application.Services.Interfaces
{
    public interface ITokenWhitelistService
    {
        Task SetCacheReponseAsync(string userId, string accessToken, object response, TimeSpan timeOut);
        Task<List<AccessTokenAndUserId>> GetKeysByRefreshTokenAsync(string refreshToken);
        Task<List<KeyWhiteList>> GetAllKeysByUserId(string userId);
        Task<KeyWhiteList> GetKeyByUserIdAndAccessToken(string userId, string accessToken);
        Task<List<AccessTokenAndUserId>> GetKeysByRefreshTokenHashedAsync(string refreshTokenHashed);

        //Task<string> GetCachedReponseAsync(string accessToken);
        //Task<bool> IsTokenBlacklistedAsync(string accessToken);
    }
}
