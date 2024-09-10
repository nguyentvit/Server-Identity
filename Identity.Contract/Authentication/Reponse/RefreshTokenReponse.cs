namespace Identity.Contract.Authentication.Reponse
{
    public record RefreshTokenReponse(
        string AccessToken,
        string RefreshToken,
        int ExpiresIn,
        string TokenType,
        string IdToken
        );
}
