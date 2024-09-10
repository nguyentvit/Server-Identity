using ErrorOr;
using Identity.Application.Common.Results;
using Identity.Domain.Common.Errors;
using MediatR;
using Newtonsoft.Json;

namespace Identity.Application.Command.RefreshTokenGoogle
{
    public class RefreshTokenGoogleCommandHandler : IRequestHandler<RefreshTokenGoogleCommand, ErrorOr<RefreshTokenResult>>
    {
        public async Task<ErrorOr<RefreshTokenResult>> Handle(RefreshTokenGoogleCommand request, CancellationToken cancellationToken)
        {
            var refreshToken = request.RefreshToken;

            var client = new HttpClient();
            var token = new HttpRequestMessage(HttpMethod.Post, "https://oauth2.googleapis.com/token")
            {
                Content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("client_id", "54512677689-2fi560s0sleddn285cmaaa7vjr6fcrhl.apps.googleusercontent.com"),
                    new KeyValuePair<string, string>("client_secret", "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"),
                    new KeyValuePair<string, string>("grant_type", "refresh_token"),
                    new KeyValuePair<string, string>("refresh_token", refreshToken)
                })
            };

            var tokenResponse = await client.SendAsync(token);
            if (!tokenResponse.IsSuccessStatusCode)
            {
                return Errors.Authentication.InvalidCredentials;
            }

            var tokenContent = await tokenResponse.Content.ReadAsStringAsync();
            var tokenResult = JsonConvert.DeserializeObject<TokenResult>(tokenContent);

            RefreshTokenResult refreshTokenResult = new(tokenResult.AccessToken, (tokenResult.RefreshToken == null) ? refreshToken : tokenResult.RefreshToken, tokenResult.ExpiresIn, tokenResult.TokenType, tokenResult.IdToken);

            return refreshTokenResult;
        }
    }
}
