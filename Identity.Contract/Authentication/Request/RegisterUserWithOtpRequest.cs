namespace Identity.Contract.Authentication.Request
{
    public record RegisterUserWithOtpRequest(string Email, string PhoneNumber, string Name, string Password, string ConfirmPassword, string Otp);
}
