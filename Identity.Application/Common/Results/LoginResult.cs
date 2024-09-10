namespace Identity.Application.Common.Results
{
    public record LoginResult(
        string AccessToken,
        string RefreshToken,
        int ExpiresIn,
        string TokenType,
        string IdToken,
        LoginUserResult User
        );
    public record LoginUserResult(
        string Id,
        string UserName,
        string Email,
        string Name
        );
}
