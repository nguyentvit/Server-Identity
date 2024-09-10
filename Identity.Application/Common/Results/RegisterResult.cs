namespace Identity.Application.Common.Results
{
    public record RegisterResult(
        bool success,
        string message,
        RegisterDataResult data
        );
    public record RegisterDataResult(
        string userId,
        string userName,
        string email,
        string url
        );

}
