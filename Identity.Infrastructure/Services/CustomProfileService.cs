using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Services;
using Identity.Domain.Identity;
using IdentityModel;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace Identity.Infrastructure.Services
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
            var email = context.Subject.Claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Email)?.Value;
            var sub = context.Subject.Claims.FirstOrDefault(c => c.Type == JwtClaimTypes.Subject)?.Value;


            var user = (string.IsNullOrEmpty(email)) ? await _userManager.FindByIdAsync(sub) : await _userManager.FindByEmailAsync(email);

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

            // add actor claim if needed
            //if (context.Subject.GetAuthenticationMethod() == OidcConstants.GrantTypes.TokenExchange)
            //{
            //    var act = context.Subject.FindFirst(JwtClaimTypes.Actor);
            //    if (act != null)
            //    {
            //        context.IssuedClaims.Add(act);
            //    }
            //}

            //return Task.CompletedTask;
        }

        public Task IsActiveAsync(IsActiveContext context)
        {
            // Kiểm tra xem người dùng có đang hoạt động hay không
            context.IsActive = true;
            return Task.CompletedTask;
        }
    }
}
