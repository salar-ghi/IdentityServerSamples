using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using IdentityModel;

namespace NitroIdentityServer;

public static class Config
{
    public static IEnumerable<IdentityResource> IdentityResources =>
        new IdentityResource[]
        {
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            new IdentityResource()
            {
                Name = "verification",
                UserClaims = new List<string>
                {
                    JwtClaimTypes.Email,
                    JwtClaimTypes.EmailVerified
                }
            }
        };

    public static IEnumerable<ApiScope> ApiScopes =>
        new List<ApiScope>
        {
            new ApiScope("api1", "My API"),
            new ApiScope("scope1"),
            new ApiScope("scope2"),
        };

    public static IEnumerable<Client> Clients =>
        new List<Client>
        {
            // m2m client credentials flow client
            new Client
            {
                ClientId = "m2m.client",
                //ClientName = "Client Credentials Client",

                AllowedGrantTypes = GrantTypes.ClientCredentials,
                ClientSecrets =
                {
                    new Secret("secret".Sha256())
                },

                //ClientSecrets = { new Secret("511536EF-F270-4058-80CA-1C89C192F69A".Sha256()) },

                AllowedScopes = { "scope1", "api1" }
            },

            // interactive client using code flow + pkce
            new Client
            {
                ClientId = "web.client",
                ClientSecrets = { new Secret("49C1A7E1-0C79-4A89-A3D6-A37998FB86B0".Sha256()) },

                AllowedGrantTypes = GrantTypes.Code,

                // where to redirect to after login
                //RedirectUris = { "https://localhost:5002/signin-oidc" },
                RedirectUris = { "https://localhost:5002/CallApi" },
                //FrontChannelLogoutUri = "https://localhost:5002/signout-oidc",
                 // where to redirect to after logout
                FrontChannelLogoutUri = "https://localhost:5002/Signout",
                //PostLogoutRedirectUris = { "https://localhost:5002/signout-callback-oidc" },
                PostLogoutRedirectUris = { "https://localhost:5002/Signout" },
                

                AllowOfflineAccess = true,
                //AllowedScopes = { "openid", "profile", "scope2" }
                //AllowedScopes = { "openid", "profile", "scope2" }
                AllowedScopes = new List<string>
                {
                    "api1" ,"scope1" , "scope2", "verification",
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile,
                }
            },
        };
}
