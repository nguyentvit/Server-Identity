namespace Identity.Infrastructure.Services
{
    public class SmtpSettings
    {
        public const string SectionName = "SmtpSettings";
        public string Host { get; init; } = null!;
        public int Port { get; init; }
        public string UserName { get; init; } = null!;
        public string Password { get; init; } = null!;
        public string FromEmail { get; init; } = null!;
        public string FromName { get; init; } = null!;
    }
}
