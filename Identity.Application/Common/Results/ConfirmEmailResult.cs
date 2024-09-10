namespace Identity.Application.Common.Results
{
    public record ConfirmEmailResult(
        string Status,
        string Message,
        ConfirmEmailUserResult User
        );
    public record ConfirmEmailUserResult(
        string Id,
        string Email,
        bool IsEmailConfirmed
        );
}
