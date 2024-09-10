using Duende.IdentityServer.ResponseHandling;
using Duende.IdentityServer.Validation;

namespace Identity.Infrastructure.Services
{
    public class CustomTokenService : ValidatedTokenRequest
    {
        public Task<TokenResponse> ProcessAsync(TokenRequestValidationResult validationResult)
        {
            throw new NotImplementedException();
        }
    }
}
