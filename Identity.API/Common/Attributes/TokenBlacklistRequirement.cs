using Identity.Application.Services.Interfaces;
using Microsoft.AspNetCore.Authorization;

namespace Identity.API.Common.Attributes
{
    public class TokenBlacklistRequirement : IAuthorizationRequirement
    {

    }
    public class TokenBlacklistHandler : AuthorizationHandler<TokenBlacklistRequirement>
    {
        private readonly ITokenBlacklistService _tokenBlacklistService;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public TokenBlacklistHandler(ITokenBlacklistService tokenBlacklistService, IHttpContextAccessor httpContextAccessor)
        {
            _tokenBlacklistService = tokenBlacklistService;
            _httpContextAccessor = httpContextAccessor;
        }

        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, TokenBlacklistRequirement requirement)
        {
            var httpContext = _httpContextAccessor.HttpContext;
            var authorizationHeader = httpContext.Request.Headers["Authorization"].ToString();

            if (!string.IsNullOrEmpty(authorizationHeader) && authorizationHeader.StartsWith("Bearer "))
            {
                var token = authorizationHeader.Substring("Bearer ".Length).Trim();

                var isBlacklisted = await _tokenBlacklistService.IsTokenBlacklistedAsync(token);
                if (!isBlacklisted)
                {
                    context.Succeed(requirement);
                    return;
                }
            }

            context.Fail();
        }
    }
}
