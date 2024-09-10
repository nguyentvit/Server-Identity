using ErrorOr;
using Identity.Application.Common.Results;
using Identity.Application.Services.Interfaces;
using Identity.Domain.Common.Errors;
using MediatR;

namespace Identity.Application.Command.RevocationLogin
{
    public class RevocationLoginCommandHandler : IRequestHandler<RevocationLoginCommand, ErrorOr<RevocationLoginResult>>
    {
        private readonly IPersistedGrantService _persistedGrantService;
        private readonly ITokenBlacklistService _blackList;
        private readonly ITokenWhitelistService _whiteList;
        private readonly IRefreshTokenHasher _refreshTokenHasher;
        public RevocationLoginCommandHandler(IPersistedGrantService persistedGrantService, ITokenBlacklistService blackList, ITokenWhitelistService whiteList, IRefreshTokenHasher refreshTokenHasher)
        {
            _persistedGrantService = persistedGrantService;
            _blackList = blackList;
            _whiteList = whiteList;
            _refreshTokenHasher = refreshTokenHasher;
        }

        public async Task<ErrorOr<RevocationLoginResult>> Handle(RevocationLoginCommand request, CancellationToken cancellationToken)
        {
            var refreshToken = request.RefreshToken;
            var userId = request.UserId;
            var accessToken = request.AccessToken;

            if (refreshToken.EndsWith("-1"))
            {
                refreshToken = _refreshTokenHasher.sha256_hash(refreshToken);
            }

            var key = await _whiteList.GetKeyByUserIdAndAccessToken(userId, accessToken);
            if (_refreshTokenHasher.sha256_hash(key.RefreshToken) ==  refreshToken)
            {
                return Errors.Authentication.InvalidCredentials;
            }

            await _persistedGrantService.RemoveGrantByRefreshTokenHashed(refreshToken);
            var keysRemove = await _whiteList.GetKeysByRefreshTokenHashedAsync(refreshToken);

            foreach (var keyRemove in keysRemove)
            {
                await _blackList.SetCacheReponseAsync(keyRemove.AccessToken, keyRemove.AccessToken, TimeSpan.FromSeconds(3600));
            }


            RevocationLoginResult revocationLoginResult = new("success", "Log out success");
            return revocationLoginResult;
        }
    }
}
