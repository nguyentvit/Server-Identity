namespace Identity.Contract.Authentication.Request
{
    public record GoogleUserInfo(
        string Sub,
        string Name,
        string GivenName,
        string FamilyName,
        string Picture,
        string Email,
        bool EmailVerified,
        string Locale
        );
}
