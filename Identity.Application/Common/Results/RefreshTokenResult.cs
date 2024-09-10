namespace Identity.Application.Common.Results
{
    public record RefreshTokenResult(
        string AccessToken,
        string RefreshToken,
        int ExpiresIn,
        string TokenType,
        string IdToken
        );
}
