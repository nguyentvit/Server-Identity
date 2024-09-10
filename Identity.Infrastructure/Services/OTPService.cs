using Identity.Application.Services.Interfaces;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Identity.Infrastructure.Services
{
    public class OTPService : IOTPService
    {
        public string GenerateOTP(int length = 6)
        {
            const string validChars = "0123456789";
            var random = new Random();
            return new string(Enumerable.Repeat(validChars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        }

        public string HashOTP(string otp)
        {
            byte[] salt;
            byte[] buffer2;
            if (otp == null)
            {
                throw new ArgumentNullException(nameof(otp));
            }

            using (Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(otp, 0x10, 0x3e8, HashAlgorithmName.SHA256))
            {
                salt = bytes.Salt;
                buffer2 = bytes.GetBytes(0x20);
            }

            byte[] dst = new byte[0x31];
            Buffer.BlockCopy(salt, 0, dst, 1, 0x10);
            Buffer.BlockCopy(buffer2, 0, dst, 0x11, 0x20);
            return Convert.ToBase64String(dst);
        }

        public bool VerifyOTP(string otp, string hashedOtp)
        {
            byte[] buffer4;
            if (hashedOtp == null)
            {
                return false;
            }

            if (otp == null)
            {
                throw new ArgumentNullException(nameof(otp));
            }

            byte[] src = Convert.FromBase64String(hashedOtp);
            if ((src.Length != 0x31) || (src[0] != 0))
            {
                return false;
            }

            byte[] dst = new byte[0x10];
            Buffer.BlockCopy(src, 1, dst, 0, 0x10);
            byte[] buffer3 = new byte[0x20];
            Buffer.BlockCopy(src, 0x11, buffer3, 0, 0x20);
            using (Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(otp, dst, 0x3e8, HashAlgorithmName.SHA256))
            {
                buffer4 = bytes.GetBytes(0x20);
            }

            return ByteArraysEqual(buffer3, buffer4);
        }

        [MethodImpl(MethodImplOptions.NoOptimization)]
        private static bool ByteArraysEqual(byte[] a, byte[] b)
        {
            if (ReferenceEquals(a, b))
            {
                return true;
            }

            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }

            var areSame = true;
            for (var i = 0; i < a.Length; i++)
            {
                areSame &= a[i] == b[i];
            }

            return areSame;
        }
    }
}
