using ErrorOr;
using Identity.Application.Common.Enum;
using Identity.Application.Common.Results;
using Identity.Application.Services.Interfaces;
using MediatR;

namespace Identity.Application.Queries.GetAllInfoLogins
{
    public class GetAllInfoLoginsQueryHandler : IRequestHandler<GetAllInfoLoginsQuery, ErrorOr<GetAllInfoLoginsResult>>
    {
        private readonly ITokenWhitelistService _whiteList;
        private readonly ITokenBlacklistService _blacklist;
        private readonly IPersistedGrantService _persistedGrantService;
        private readonly IRefreshTokenHasher _refreshTokenHasher;
        public GetAllInfoLoginsQueryHandler(ITokenWhitelistService whiteList, ITokenBlacklistService blacklist, IPersistedGrantService persistedGrantService, IRefreshTokenHasher refreshTokenHasher)
        {
            _whiteList = whiteList;
            _blacklist = blacklist;
            _persistedGrantService = persistedGrantService;
            _refreshTokenHasher = refreshTokenHasher;
        }

        public async Task<ErrorOr<GetAllInfoLoginsResult>> Handle(GetAllInfoLoginsQuery request, CancellationToken cancellationToken)
        {

            var keys = await _whiteList.GetAllKeysByUserId(request.userId);
            var persistedGrants = await _persistedGrantService.GetAllGrantsBySubIdAsync(request.userId);

            var keysResult = new List<GetAllInfoLoginsAccessResult>();
            var darkList = new List<string>();

            

            foreach (var key in keys)
            {
                var refreshHash = _refreshTokenHasher.sha256_hash(key.RefreshToken).ToLower();
                darkList.Add(refreshHash);

                if (!await _blacklist.IsTokenBlacklistedAsync(key.AccessToken))
                {
                    keysResult.Add(new GetAllInfoLoginsAccessResult(key.AccessToken, key.RefreshToken, StatusHased.Primitive.ToString()));
                }
            }

            foreach (var persistedGrant in persistedGrants)
            {
                var refreshToken = persistedGrant.Key.ToLower();
                if (!darkList.Contains(refreshToken))
                {
                    keysResult.Add(new GetAllInfoLoginsAccessResult(null, persistedGrant.Key, StatusHased.Hashed.ToString()));
                }
            }


            GetAllInfoLoginsResult result = new(request.userId, keysResult.Count, keysResult);

            return result;
        }
    }
}
