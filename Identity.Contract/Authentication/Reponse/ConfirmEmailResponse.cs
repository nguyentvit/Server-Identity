namespace Identity.Contract.Authentication.Reponse
{
    public record ConfirmEmailResponse(
        string Status,
        string Message,
        ConfirmEmailUserResponse User
        );
    public record ConfirmEmailUserResponse(
        string Id,
        string Email,
        bool IsEmailConfirmed
        );
}
