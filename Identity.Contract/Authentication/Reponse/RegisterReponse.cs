namespace Identity.Contract.Authentication.Reponse
{
    public record RegisterReponse(
        bool success,
        string message,
        RegisterDataReponse data
        );
    public record RegisterDataReponse(
        string userId,
        string userName,
        string email,
        string url
        );
}
