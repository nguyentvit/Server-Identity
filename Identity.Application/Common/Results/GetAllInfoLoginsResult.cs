namespace Identity.Application.Common.Results
{
    public record GetAllInfoLoginsResult(
        string UserId,
        int Count,
        List<GetAllInfoLoginsAccessResult> Access
        );
    public record GetAllInfoLoginsAccessResult(
        string AccessToken,
        string RefreshToken,
        string StatusHashed
        );
}
