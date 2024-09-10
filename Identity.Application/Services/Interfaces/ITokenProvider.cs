using Identity.Domain.Identity;

namespace Identity.Application.Services.Interfaces
{
    public interface ITokenProvider
    {
        string GenerateEmailConfirmationToken(ApplicationUser user);
        string ValidateTokenEmailConfirmationToken(string token);
        string GenerateResetPwToken(ApplicationUser user);
        string ValidateResetPasswordToken(string token);
    }
}
