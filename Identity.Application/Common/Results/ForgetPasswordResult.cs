namespace Identity.Application.Common.Results
{
    public record ForgetPasswordResult(
        string Status,
        string Message,
        string Email,
        string Url
        );
}
