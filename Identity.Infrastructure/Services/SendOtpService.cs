using Identity.Application.Services.Interfaces;
using Microsoft.Extensions.Caching.Distributed;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using StackExchange.Redis;

namespace Identity.Infrastructure.Services
{
    public class SendOtpService : ISendOtpService
    {
        private readonly IDistributedCache _distributedCache;
        private readonly IConnectionMultiplexer _connectionMultiplexer;
        public SendOtpService(IDistributedCache distributedCache, IConnectionMultiplexer connectionMultiplexer)
        {
            _distributedCache = distributedCache;
            _connectionMultiplexer = connectionMultiplexer;

            if (!_connectionMultiplexer.IsConnected)
            {
                throw new Exception("Could not connect to Redis.");
            }
        }

        public async Task<string> GetCachedReponseAsync(string email)
        {
            var cacheKey = $"VerifyOtp:Email:{email}";
            var cacheResponse =  await _distributedCache.GetStringAsync(cacheKey);
            return string.IsNullOrEmpty(cacheResponse) ? null! : cacheResponse;
        }

        public async Task Remove(string email)
        {
            var cacheKey = $"VerifyOtp:Email:{email}";
            var existingCache = await _distributedCache.GetStringAsync(cacheKey);
            if (existingCache != null)
            {
                await _distributedCache.RemoveAsync(cacheKey);
            }
        }

        public async Task SetCacheReponseAsync(string email, object response, TimeSpan timeOut)
        {
            if (response == null)
                return;

            var cacheKey = $"VerifyOtp:Email:{email}";

            var existingCache = await _distributedCache.GetStringAsync(cacheKey);
            if (existingCache != null)
            {
                await _distributedCache.RemoveAsync(cacheKey);
            }

            var serializerResponse = JsonConvert.SerializeObject(response, new JsonSerializerSettings
            {
                ContractResolver = new CamelCasePropertyNamesContractResolver()
            });

            await _distributedCache.SetStringAsync(cacheKey, serializerResponse, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = timeOut
            });
        }
    }
}
