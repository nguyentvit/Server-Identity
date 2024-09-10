namespace Identity.Application.Services.Interfaces
{
    public interface IOTPService
    {
        string GenerateOTP(int length = 6);
        string HashOTP(string otp);
        bool VerifyOTP(string otp, string hashedOtp);
    }
}
