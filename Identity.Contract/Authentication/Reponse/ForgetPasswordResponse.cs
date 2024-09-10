namespace Identity.Contract.Authentication.Reponse
{
    public record ForgetPasswordResponse(
        string Status,
        string Message,
        string Email,
        string Url
        );
}
