using ErrorOr;
using Identity.Application.Common.Results;
using Identity.Application.Services.Interfaces;
using Identity.Domain.Common.Errors;
using MediatR;
using Newtonsoft.Json;
namespace Identity.Application.Command.RefreshToken
{
    public class RefreshTokenCommandHandler : IRequestHandler<RefreshTokenCommand, ErrorOr<RefreshTokenResult>>
    {
        private readonly ITokenWhitelistService _whiteList;
        private readonly ITokenBlacklistService _blacklist;
        private readonly IPersistedGrantService _persistedGrantService;
        public RefreshTokenCommandHandler(ITokenWhitelistService whiteList, ITokenBlacklistService blacklist, IPersistedGrantService persistedGrantService)
        {
            _whiteList = whiteList;
            _blacklist = blacklist;
            _persistedGrantService = persistedGrantService;
        }

        public async Task<ErrorOr<RefreshTokenResult>> Handle(RefreshTokenCommand request, CancellationToken cancellationToken)
        {
            var keys = await _whiteList.GetKeysByRefreshTokenAsync(request.RefreshToken);
            var key = keys.FirstOrDefault();

            if (key == null)
            {
                return Errors.Authentication.InvalidCredentials;
            }

            string accessToken = key.AccessToken;
            string userId = key.UserId;

            var client = new HttpClient();
            var token = new HttpRequestMessage(HttpMethod.Post, "https://localhost:7100/connect/token")
            {
                Content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("client_id", "magic"),
                    new KeyValuePair<string, string>("client_secret", "secret"),
                    new KeyValuePair<string, string>("grant_type", "refresh_token"),
                    new KeyValuePair<string, string>("refresh_token", request.RefreshToken)
                })
            };

            var tokenResponse = await client.SendAsync(token);
            if (!tokenResponse.IsSuccessStatusCode)
            {
                return Errors.Authentication.InvalidCredentials;
            }

            var tokenContent = await tokenResponse.Content.ReadAsStringAsync();
            var tokenResult = JsonConvert.DeserializeObject<TokenResult>(tokenContent);

            await _blacklist.SetCacheReponseAsync(accessToken, accessToken, TimeSpan.FromSeconds(tokenResult.ExpiresIn));


            var obj = new Dictionary<string, string>();

            obj.Add("userId", userId);
            obj.Add("accessToken", tokenResult.AccessToken);
            obj.Add("refreshToken", tokenResult.RefreshToken);

            await _whiteList.SetCacheReponseAsync(userId, tokenResult.AccessToken, obj, TimeSpan.FromSeconds(tokenResult.ExpiresIn));

            RefreshTokenResult refreshTokenResult = new(tokenResult.AccessToken, tokenResult.RefreshToken, tokenResult.ExpiresIn, tokenResult.TokenType, tokenResult.IdToken);

            return refreshTokenResult;
        }
    }
}
