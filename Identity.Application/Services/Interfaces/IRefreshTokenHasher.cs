namespace Identity.Application.Services.Interfaces
{
    public interface IRefreshTokenHasher
    {
        string sha256_hash(string refreshToken);
    }
}
