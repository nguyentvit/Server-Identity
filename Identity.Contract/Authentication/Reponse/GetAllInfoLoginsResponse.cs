namespace Identity.Contract.Authentication.Reponse
{
    public record GetAllInfoLoginsResponse(
        string UserId,
        int Count,
        List<GetAllInfoLoginsAccessResponse> Access
        );
    public record GetAllInfoLoginsAccessResponse(
        string AccessToken,
        string RefreshToken,
        string StatusHashed
        );
}
