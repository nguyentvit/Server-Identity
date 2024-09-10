using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using IdentityModel;

namespace Identity.Infrastructure
{
    public static class IdentityConfig
    {
        public const string Admin = "admin";
        public const string Customer = "customer";

        public static IEnumerable<IdentityResource> IdentityResources =>
            new List<IdentityResource>()
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Email(),
                new IdentityResources.Profile()
            };

        public static IEnumerable<ApiScope> ApiScopes =>
            new List<ApiScope>()
            {
                new ApiScope(name: "read", displayName: "Read your data"),
                new ApiScope(name: "write", displayName: "Write your data"),
                new ApiScope(name: "delete", displayName: "Delete your data"),
                new ApiScope("magic", "Magic Server")
            };

        public static IEnumerable<Client> Get =>
            new List<Client>()
            {
                new Client
                {
                    ClientId = "service.client",
                    ClientSecrets = {new Secret("secret".Sha256()) },
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    AllowedScopes = {"api1", "api2.read_only"}
                },
                new Client
                {
                    ClientId = "magic",
                    ClientSecrets = {new Secret("secret".Sha256())},
                    AllowedGrantTypes = {GrantType.ResourceOwnerPassword, OidcConstants.GrantTypes.TokenExchange},
                    AllowOfflineAccess = true,
                    AllowedScopes = { "magic",
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Email,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.OfflineAccess
                    },
                    AccessTokenLifetime = 3600,
                    AbsoluteRefreshTokenLifetime = 2592000,
                    SlidingRefreshTokenLifetime = 1296000,
                    RefreshTokenUsage = TokenUsage.OneTimeOnly,
                    RefreshTokenExpiration = TokenExpiration.Sliding,
                    RedirectUris = { "https://localhost:7100/signin-oidc" },
                    PostLogoutRedirectUris = { "https://localhost:7100/signout-callback-oidc" },

                },
                new Client
                {
                    ClientId = "web-client",
                    ClientSecrets = { new Secret("web-client-secret".Sha256()) },
                    AllowedGrantTypes = GrantTypes.Code,
                    RedirectUris = { "https://localhost:7100/user/signin-google" },
                    PostLogoutRedirectUris = { "https://localhost:7100/signout-callback-oidc" },
                    AllowedScopes = { "openid", "profile", "email", "offline_access", "magic" },
                    AllowOfflineAccess = true // Cấp refresh token nếu cần
                }
                //,
                //new Client
                //{
                //    ClientId = "custom-client",
                //    ClientSecrets = { new Secret("custom-client-secret".Sha256()) },
                //    AllowedGrantTypes = { OidcConstants.GrantTypes.TokenExchange },
                //    AllowedScopes = { "magic",
                //        IdentityServerConstants.StandardScopes.OpenId,
                //        IdentityServerConstants.StandardScopes.Email,
                //        IdentityServerConstants.StandardScopes.Profile,
                //    },
                //}
            };
    }
}
