namespace Identity.Application.Common.Results
{
    public record RegisterUserWithOtpResult(
        bool success,
        string message,
        RegisterUserDataWithOtpResult data
        );
    public record RegisterUserDataWithOtpResult(
        string userId,
        string userName,
        string email
        );
}
