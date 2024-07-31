using Duende.IdentityServer;
using NitroIdentityServer.Data;
using NitroIdentityServer.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Serilog;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using NitroIdentityServer.Services;

namespace NitroIdentityServer;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddRazorPages();

        builder.Services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));

        builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        builder.Services
            .AddIdentityServer(options =>
            {
                options.UserInteraction.LoginUrl = "";
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;

                // see https://docs.duendesoftware.com/identityserver/v6/fundamentals/resources/
                options.EmitStaticAudienceClaim = true;
            })
            .AddInMemoryIdentityResources(Config.IdentityResources)
            .AddInMemoryApiScopes(Config.ApiScopes)
            .AddInMemoryClients(Config.Clients)
            .AddAspNetIdentity<ApplicationUser>()
            .AddDeveloperSigningCredential()
            .AddTestUsers(TestUsers.Users);

        //var authenticationBuilder = builder.Services.AddAuthentication();
        //var googleClientId = builder.Configuration["Authentication:Google:ClientId"];
        //var googleClientSecret = builder.Configuration["Authentication:Google:ClientSecret"];
        //authenticationBuilder.AddCookie("Cookie", options =>
        //{
        //    options.LoginPath = "/"
        //});
        //if (googleClientId != null && googleClientSecret != null)
        //{
        //    authenticationBuilder.AddGoogle("Google", options =>
        //    {
        //        options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;

        //        options.ClientId = googleClientId;
        //        options.ClientSecret = googleClientSecret;
        //    });
        //}

        var jwtSettings = builder.Configuration.GetSection("JwtSettings");
        var key = Encoding.ASCII.GetBytes(jwtSettings["Secret"]);

        builder.Services.AddAuthentication()
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtSettings["Issuer"],
                    ValidAudience = jwtSettings["Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(key)
                };
                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = context =>
                    {
                        var token = context.SecurityToken as JwtSecurityToken;
                        if (TokenBlacklist.IsBlacklisted(token.RawData))
                        {
                            context.Fail("Token has been blacklisted");
                        }
                        return Task.CompletedTask;
                    }
                };
            })
            //.AddGoogle(options =>
            //{
            //    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
            //    // register your IdentityServer with Google at https://console.developers.google.com
            //    // enable the Google+ API
            //    // set the redirect URI to https://localhost:5001/signin-google
            //    options.ClientId = "copy client ID from Google here";
            //    options.ClientSecret = "copy client secret from Google here";
            //})
            .AddOpenIdConnect("oidc", "Demo IdentityServer", options =>
            {
                options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                options.SignOutScheme = IdentityServerConstants.SignoutScheme;
                options.SaveTokens = true;

                options.Authority = "https://demo.duendesoftware.com";
                options.ClientId = "interactive.confidential";
                options.ClientSecret = "secret";
                options.ResponseType = "code";

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name",
                    RoleClaimType = "role"
                };
            });

        return builder.Build();
    }

    public static WebApplication ConfigurePipeline(this WebApplication app)
    {
        app.UseSerilogRequestLogging();

        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        app.UseStaticFiles();
        app.UseRouting();

        app.UseIdentityServer();
        app.UseAuthorization();

        app.MapRazorPages()
            .RequireAuthorization();

        return app;
    }
}