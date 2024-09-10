using Identity.Application.Services.Interfaces;
using System.Security.Cryptography;
using System.Text;

namespace Identity.Infrastructure.Services
{
    public class RefreshTokenHasher : IRefreshTokenHasher
    {
        public string sha256_hash(string refreshToken)
        {
            var keyseparator = ":";
            var granttype = "refresh_token";
            refreshToken = refreshToken + keyseparator + granttype;

            var sb = new StringBuilder();

            using (var hash = SHA256.Create())
            {
                var enc = Encoding.UTF8;
                byte[] result = hash.ComputeHash(enc.GetBytes(refreshToken));

                foreach (byte b in result)
                    sb.Append(b.ToString("x2"));
            }

            return sb.ToString();
        }
    }
}
