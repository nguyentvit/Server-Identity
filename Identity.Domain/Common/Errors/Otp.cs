using ErrorOr;

namespace Identity.Domain.Common.Errors
{
    public static partial class Errors
    {
        public static class Otp
        {
            public static Error OtpInvalid => Error.Conflict(
                code: "Otp.OtpInvalid",
                description: "Invalid Otp"
                );
        }
    }
}
