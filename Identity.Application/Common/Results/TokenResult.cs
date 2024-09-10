using Newtonsoft.Json;

namespace Identity.Application.Common.Results
{
    public record TokenResult(
        [JsonProperty("access_token")]
        string AccessToken,
        [JsonProperty("refresh_token")]
        string RefreshToken,
        [JsonProperty("expires_in")]
        int ExpiresIn,
        [JsonProperty("token_type")]
        string TokenType,
        [JsonProperty("id_token")]
        string IdToken,
        [JsonProperty("sub")]
        string SubId
        );

}
