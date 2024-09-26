namespace Identity.Contract.Authentication.Reponse
{
    public record RegisterUserWithOtpResponse(
        bool success,
        string message,
        RegisterUserWithOtpDataResponse data);
    public record RegisterUserWithOtpDataResponse(
        string userId,
        string userName,
        string email
        );
}
