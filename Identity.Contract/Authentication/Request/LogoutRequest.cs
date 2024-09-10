namespace Identity.Contract.Authentication.Request
{
    public record LogoutRequest(string AccessToken, string RefreshToken);
}
