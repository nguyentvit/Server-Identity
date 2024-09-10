namespace Identity.Contract.Authentication
{
    public record RegisterRequest(string Email, string PhoneNumber, string Name, string Password, string ConfirmPassword);
}
