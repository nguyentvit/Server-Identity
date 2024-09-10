namespace Identity.Application.Services.Interfaces
{
    public interface ITokenBlacklistService
    {
        Task SetCacheReponseAsync(string accessToken, object response, TimeSpan timeOut);
        Task<string> GetCachedReponseAsync(string accessToken);
        Task<bool> IsTokenBlacklistedAsync(string accessToken);
    }
}
