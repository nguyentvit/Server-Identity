using Identity.Application.Services.Interfaces;
using Microsoft.AspNetCore.Http;

namespace Identity.Infrastructure.Services
{
    public class IpAddress : IIpAddress
    {
        private readonly HttpContextAccessor _contextAccessor;
        private readonly string host;
        private readonly string scheme;
        public IpAddress(HttpContextAccessor contextAccessor)
        {
            _contextAccessor = contextAccessor;
            host = _contextAccessor.HttpContext?.Request?.Host.ToString();
            scheme = _contextAccessor.HttpContext?.Request.Scheme.ToString();
        }
        string IIpAddress.IpAddress => $"{scheme}://{host}";
    }
}
