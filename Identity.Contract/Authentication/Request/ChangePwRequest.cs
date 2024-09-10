namespace Identity.Contract.Authentication.Request
{
    public record ChangePwRequest(string Password, string ConfirmPassword);
}
