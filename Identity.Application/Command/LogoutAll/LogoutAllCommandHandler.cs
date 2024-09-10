using ErrorOr;
using Identity.Application.Common.Results;
using Identity.Application.Services.Interfaces;
using MediatR;

namespace Identity.Application.Command.LogoutAll
{
    public class LogoutAllCommandHandler : IRequestHandler<LogoutAllCommand, ErrorOr<LogoutResult>>
    {
        private readonly IPersistedGrantService _persistedGrantService;
        private readonly ITokenWhitelistService _whiteList;
        private readonly ITokenBlacklistService _blackList;
        public LogoutAllCommandHandler(IPersistedGrantService persistedGrantService, ITokenWhitelistService whiteList, ITokenBlacklistService blackList)
        {
            _persistedGrantService = persistedGrantService;
            _whiteList = whiteList;
            _blackList = blackList;
        }
        public async Task<ErrorOr<LogoutResult>> Handle(LogoutAllCommand request, CancellationToken cancellationToken)
        {
            var key = await _whiteList.GetKeyByUserIdAndAccessToken(request.UserId, request.AccessToken);
            await _persistedGrantService.RemoveAllGrantsBySubIdExceptItSelf(request.UserId, key.RefreshToken);

            var whiteKeys = await _whiteList.GetAllKeysByUserId(request.UserId);
            foreach ( var whiteKey in whiteKeys )
            {
                if (whiteKey.AccessToken != key.AccessToken)
                {
                    await _blackList.SetCacheReponseAsync(whiteKey.AccessToken, whiteKey.AccessToken, TimeSpan.FromSeconds(3600));
                }
            }

            LogoutResult logoutResult = new("success", "Log out all success");
            return logoutResult;
        }
    }
}
