using Duende.IdentityServer.EntityFramework.Entities;
using Duende.IdentityServer.Models;
using ErrorOr;
using Identity.Application.Common.Results;
using Identity.Application.Services.Interfaces;
using Identity.Domain.Common.Models;
using Identity.Domain.Identity;
using IdentityModel;
using MediatR;
using Microsoft.AspNetCore.Identity;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;

namespace Identity.Application.Command.LoginGoogle
{
    public class LoginGoogleCommandHandler : IRequestHandler<LoginGoogleCommand, ErrorOr<LoginResult>>
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ITokenWhitelistService _whiteList;
        private readonly IUnitOfWork _unitOfWork;
        public LoginGoogleCommandHandler(UserManager<ApplicationUser> userManager, ITokenWhitelistService whiteList, IUnitOfWork unitOfWork)
        {
            _userManager = userManager;
            _whiteList = whiteList;
            _unitOfWork = unitOfWork;
        }

        public async Task<ErrorOr<LoginResult>> Handle(LoginGoogleCommand request, CancellationToken cancellationToken)
        {
            var authorizationCode = request.AuthorizationCode;

            var client = new HttpClient();

            var token = new HttpRequestMessage(HttpMethod.Post, "https://localhost:7100/connect/token")
            {
                Content = new FormUrlEncodedContent(new[]
                    {
                        new KeyValuePair<string, string>("grant_type", OidcConstants.GrantTypes.TokenExchange),
                        new KeyValuePair<string, string>("subject_token", authorizationCode),
                        new KeyValuePair<string, string>("subject_token_type", OidcConstants.TokenTypeIdentifiers.AccessToken),
                        new KeyValuePair<string, string>("client_id", "magic"),
                        new KeyValuePair<string, string>("client_secret", "secret"),
                        new KeyValuePair<string, string>("scope", "email openid profile offline_access")
                    })
            };

            var tokenResponse = await client.SendAsync(token);

            if (!tokenResponse.IsSuccessStatusCode)
            {
                throw new Exception();
            }

            var tokenContent = await tokenResponse.Content.ReadAsStringAsync();
            var tokenResult = JsonConvert.DeserializeObject<TokenResult>(tokenContent);

            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(tokenResult.AccessToken);
            var claims = jwtToken.Claims;

            var subId = claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Subject)?.Value;

            var user = await _userManager.FindByIdAsync(subId);

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
