namespace Identity.Contract.Authentication.Request
{
    public record VerifyOtpEmailRequest(string Email, string Otp);
}
