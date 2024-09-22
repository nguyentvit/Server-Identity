using ErrorOr;
using Identity.Application.Common.Results;
using Identity.Application.Services.Interfaces;
using Identity.Domain.Common.Errors;
using Identity.Domain.Identity;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Newtonsoft.Json;

namespace Identity.Application.Command.Login
{
    public class LoginCommandHandler : IRequestHandler<LoginCommand, ErrorOr<LoginResult>>
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ITokenWhitelistService _whiteList;

        public LoginCommandHandler(UserManager<ApplicationUser> userManager, ITokenWhitelistService whiteList)
        {
            _userManager = userManager;
            _whiteList = whiteList;
        }
        public async Task<ErrorOr<LoginResult>> Handle(LoginCommand request, CancellationToken cancellationToken)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password))
            {
                return Errors.Authentication.InvalidCredentials;
            }
            
            var client = new HttpClient();

            var token = new HttpRequestMessage(HttpMethod.Post, "http://192.168.1.11:7100/connect/token")
            {
                Content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", "password"),
                    new KeyValuePair<string, string>("username", request.Email),
                    new KeyValuePair<string, string>("password", request.Password),
                    new KeyValuePair<string, string>("client_id", "magic"),
                    new KeyValuePair<string, string>("client_secret", "secret"),
                    new KeyValuePair<string, string>("scope", "email openid profile offline_access")
                })
            };

            var tokenResponse = await client.SendAsync(token);
            if (!tokenResponse.IsSuccessStatusCode)
            {
                var errorContent = await tokenResponse.Content.ReadAsStringAsync();
                return Errors.Authentication.InvalidCredentials;
            }
            

            var tokenContent = await tokenResponse.Content.ReadAsStringAsync();
            var tokenResult = JsonConvert.DeserializeObject<TokenResult>(tokenContent);

            var obj = new Dictionary<string, string>();
            obj.Add("userId", user.Id);
            obj.Add("accessToken", tokenResult.AccessToken);
            obj.Add("refreshToken", tokenResult.RefreshToken);

            await _whiteList.SetCacheReponseAsync(user.Id, tokenResult.AccessToken, obj, TimeSpan.FromSeconds(tokenResult.ExpiresIn));

            LoginUserResult loginUserResult = new(user.Id, user.UserName, user.Email, user.Name);
            LoginResult loginResult = new(tokenResult.AccessToken, tokenResult.RefreshToken, tokenResult.ExpiresIn, tokenResult.TokenType, tokenResult.IdToken, loginUserResult);

            return loginResult;
        }
    }
}
