using ErrorOr;
using Identity.Application.Common.Results;
using Identity.Application.Services.Interfaces;
using Identity.Domain.Common.Errors;
using MediatR;

namespace Identity.Application.Command.Logout
{
    public class LogoutCommandHandler : IRequestHandler<LogoutCommand, ErrorOr<LogoutResult>>
    {
        private readonly ITokenBlacklistService _blackList;
        public LogoutCommandHandler(ITokenBlacklistService blackList)
        {
            _blackList = blackList;
        }
        public async Task<ErrorOr<LogoutResult>> Handle(LogoutCommand request, CancellationToken cancellationToken)
        {

            var accessToken = request.AccessToken;
            var refreshToken = request.RefreshToken;

            var client = new HttpClient();

            var token = new HttpRequestMessage(HttpMethod.Post, "http://192.168.1.11:7100/connect/revocation")
            {
                Content = new FormUrlEncodedContent(new[]
                {   new KeyValuePair<string, string>("client_id", "magic"),
                    new KeyValuePair<string, string>("client_secret", "secret"),
                    new KeyValuePair<string, string>("token", refreshToken),
                    new KeyValuePair<string, string>("token_type_hint", "refresh_token")
                })
            };

            var tokenResponse = await client.SendAsync(token);
            if (!tokenResponse.IsSuccessStatusCode)
            {
                return Errors.Authentication.InvalidCredentials;
            }

            var timespan = TimeSpan.FromSeconds(3600);

            await _blackList.SetCacheReponseAsync(accessToken, accessToken, timespan);


            LogoutResult logoutResult = new("success", "Log out success");

            return logoutResult;
        }
    }
}
