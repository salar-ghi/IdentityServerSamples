using Microsoft.AspNetCore.Authentication;

namespace NitroClient.Infra;

public static class AuthService
{
    public static IServiceCollection AddServices(this IServiceCollection services)
    {
        services.AddAuthentication(options =>
        {
            options.DefaultScheme = "Cookies";
            options.DefaultChallengeScheme = "oidc";
        })
            .AddCookie("Cookies")
            .AddOpenIdConnect("oidc", options =>
            {
                options.Authority = "https://localhost:5001";

                options.ClientId = "web.client";
                options.ClientSecret = "49C1A7E1-0C79-4A89-A3D6-A37998FB86B0";
                options.ResponseType = "code";

                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.Scope.Add("api1");
                options.Scope.Add("verification");
                options.ClaimActions.MapJsonKey("email_verified", "email_verified");
                options.GetClaimsFromUserInfoEndpoint = true;
                //options.Scope.Add("api1");
                //options.Scope.Add("scope1");

                options.MapInboundClaims = false; // Don't rename claim types

                options.SaveTokens = true;
            });

        return services;
    }
}
