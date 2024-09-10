using Identity.Application.Services.Interfaces;
using Microsoft.Extensions.Caching.Distributed;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using StackExchange.Redis;

namespace Identity.Infrastructure.Services
{
    public class RedisTokenBlacklistService : ITokenBlacklistService
    {
        private readonly IDistributedCache _distributedCache;
        private readonly IConnectionMultiplexer _connectionMultiplexer;
        public RedisTokenBlacklistService(IDistributedCache distributedCache, IConnectionMultiplexer connectionMultiplexer)
        {
            _distributedCache = distributedCache;
            _connectionMultiplexer = connectionMultiplexer;

            if (!_connectionMultiplexer.IsConnected)
            {
                throw new Exception("Could not connect to Redis.");
            }
        }

        public async Task<string> GetCachedReponseAsync(string accessToken)
        {
            var cacheKey = $"BlackList:AccessToken:{accessToken}";
            var cacheReponse = await _distributedCache.GetStringAsync(cacheKey);
            return string.IsNullOrEmpty(cacheReponse) ? null : cacheReponse;
        }

        public async Task SetCacheReponseAsync(string accessToken, object response, TimeSpan timeOut)
        {
            if (response == null)
                return;

            var cacheKey = $"BlackList:AccessToken:{accessToken}";

            var serializerReponse = JsonConvert.SerializeObject(response, new JsonSerializerSettings()
            {
                ContractResolver = new CamelCasePropertyNamesContractResolver()
            });

            await _distributedCache.SetStringAsync(cacheKey, serializerReponse, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = timeOut
            });
        }

        public async Task<bool> IsTokenBlacklistedAsync(string accessToken)
        {
            var cacheKey = $"BlackList:AccessToken:{accessToken}";

            var result = await _distributedCache.GetStringAsync(cacheKey);
            return result != null;
        }
    }
}
