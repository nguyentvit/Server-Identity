using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Identity.Domain.Identity;
using IdentityModel;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace Identity.API.Common
{
    public class CustomProfileService : IProfileService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        public CustomProfileService(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }
        public async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var user = await _userManager.GetUserAsync(context.Subject);

            // Lấy các claims của người dùng từ UserManager
            var claims = await _userManager.GetClaimsAsync(user);

            // Thêm các claims về vai trò vào danh sách claims
            var roles = await _userManager.GetRolesAsync(user);
            foreach (var role in roles)
            {
                claims.Add(new Claim(JwtClaimTypes.Role, role));
            }

            // Cung cấp các claims cho token
            context.IssuedClaims = (List<Claim>)claims;
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            context.IsActive = true;
            return Task.CompletedTask;
        }
    }
}
