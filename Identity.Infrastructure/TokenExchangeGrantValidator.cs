using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Duende.IdentityServer.Validation;
using Identity.Application.Common.Results;
using Identity.Application.Services.Interfaces;
using Identity.Domain.Identity;
using IdentityModel;
using Microsoft.AspNetCore.Identity;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;

namespace Identity.Infrastructure
{
    public class TokenExchangeGrantValidator : IExtensionGrantValidator
    {
        private const string clientId = "54512677689-2fi560s0sleddn285cmaaa7vjr6fcrhl.apps.googleusercontent.com";
        private const string clientSecret = "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";
        private readonly ITokenService _tokenService;
        private readonly UserManager<ApplicationUser> _userManager;
        public TokenExchangeGrantValidator(ITokenService tokenService, UserManager<ApplicationUser> userManager)
        {
            _tokenService = tokenService;
            _userManager = userManager;
        }
        public string GrantType => OidcConstants.GrantTypes.TokenExchange;

        public async Task ValidateAsync(ExtensionGrantValidationContext context)
        {
            // defaults
            context.Result = new GrantValidationResult(TokenRequestErrors.InvalidRequest);
            var customResponse = new Dictionary<string, object>
            {
                {OidcConstants.TokenResponse.IssuedTokenType, OidcConstants.TokenTypeIdentifiers.AccessToken}
            };

            var subjectToken = context.Request.Raw.Get(OidcConstants.TokenRequest.SubjectToken);
            var subjectTokenType = context.Request.Raw.Get(OidcConstants.TokenRequest.SubjectTokenType);

            // mandatory parameters
            if (string.IsNullOrWhiteSpace(subjectToken))
            {
                return;
            }

            if (!string.Equals(subjectTokenType, OidcConstants.TokenTypeIdentifiers.AccessToken))
            {
                return;
            }

            var client = new HttpClient();

            var tokenUrl = "https://oauth2.googleapis.com/token";

            var token = new HttpRequestMessage(HttpMethod.Post, tokenUrl)
            {
                Content = new FormUrlEncodedContent(new[]
                {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("code", subjectToken),
                new KeyValuePair<string, string>("redirect_uri", "https://localhost:7100/api/v1/Account/signin-google"),
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("client_secret", clientSecret),
                })
            };

            var tokenResponse = await client.SendAsync(token);

            if (!tokenResponse.IsSuccessStatusCode)
            {
                return;
            }

            var tokenContent = await tokenResponse.Content.ReadAsStringAsync();
            var tokenResult = JsonConvert.DeserializeObject<TokenResult>(tokenContent);

            var idToken = tokenResult.IdToken;
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(idToken);
            var claims = jwtToken.Claims;


            var subId = claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Subject)?.Value;
            var email = claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Email)?.Value;
            var name = claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Name)?.Value;

            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                user = new ApplicationUser()
                {
                    UserName = email,
                    Id = subId,
                    Email = email,
                    Name = name,
                    EmailConfirmed = true
                };

                var result = await _userManager.CreateAsync(user);

                if (result.Succeeded)
                {
                    var claimsToAdd = new[]
                {
                    new Claim(ClaimTypes.Name, user.Name),
                    new Claim(ClaimTypes.Role, IdentityConfig.Customer)
                };

                    await _userManager.AddToRoleAsync(user, IdentityConfig.Customer);
                    await _userManager.AddClaimsAsync(user, claimsToAdd);
                }
                else
                {
                    throw new Exception();
                }
            }

            var request = context.Request;

            var accessTokenLifeTime = request.AccessTokenLifetime;
            var iss = request.IssuerName;
            var scopes = request.RequestedScopes;
            var client_id = request.ClientId;
            var auth_time = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var expiration = auth_time + accessTokenLifeTime;

            var claimsToCreate = new List<Claim>()
            {
                new Claim(JwtClaimTypes.Issuer, iss),
                new Claim(JwtClaimTypes.NotBefore, auth_time.ToString()),
                new Claim(JwtClaimTypes.IssuedAt, auth_time.ToString()),
                new Claim(JwtClaimTypes.Expiration, expiration.ToString()),
                new Claim(JwtClaimTypes.Audience, $"{iss}/resources"),
                new Claim(JwtClaimTypes.ClientId, client_id),
                new Claim(JwtClaimTypes.Subject, user.Id),
                new Claim(JwtClaimTypes.IdentityProvider, "google"),
                new Claim(JwtClaimTypes.AuthenticationTime, auth_time.ToString()),
                new Claim(JwtClaimTypes.Email, email)
            };
            
            foreach (var scope in scopes)
            {
                claimsToCreate.Add(new Claim(JwtClaimTypes.Scope, scope));
            }


            var accessToken = await _tokenService.CreateAccessTokenAsync(new TokenCreationRequest()
            {
                Subject = new ClaimsPrincipal(new ClaimsIdentity(claimsToCreate)),
                ValidatedRequest = context.Request,
                ValidatedResources = context.Request.ValidatedResources,

            });
            var accessTokenString = await _tokenService.CreateSecurityTokenAsync(accessToken);

            claims.Append(new Claim(JwtClaimTypes.Subject, user.Id));
            context.Result = new GrantValidationResult(user.Id, GrantType, claims);

        }
    }
}
