using Duende.IdentityServer.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using NitroIdentityJwt.Data;
using NitroIdentityJwt.Models;
using NitroIdentityJwt.Service;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.Services.AddIdentityServer()
    .AddInMemoryClients(new List<Client>
    {
        new Client
        {
            ClientId = "client_id",
            AllowedGrantTypes = GrantTypes.ClientCredentials,
            ClientSecrets = {new Secret("client_secret".Sha256()) },
            AllowedScopes = { "api1" }
        }
    })
    .AddInMemoryApiResources(new List<ApiResource>
    {
        new ApiResource("api1", "My API")
    })
    .AddInMemoryApiScopes(new List<ApiScope>
    {
        new ApiScope("api1", "My API")
    })
    .AddDeveloperSigningCredential();

var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var key = Encoding.ASCII.GetBytes(jwtSettings["Secret"]);
//var key = Encoding.UTF8.GetBytes(jwtSettings["Secret"]);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        //ValidateIssuer = true,
        //ValidateAudience = true,
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true,
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
}).AddMicrosoftIdentityWebApi(builder.Configuration.GetSection(""));

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("WriteAccess", policy => policy.RequireClaim("permissions", Permissions.CreateTerm, Permissions.UpdateTerm));
    options.AddPolicy("DeleteAccess", policy => policy.RequireClaim("permissions", Permissions.DeleteTerm));
    options.AddPolicy("RequireAdminRole", policy => policy.RequireRole("Admin"));
});

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.ResolveConflictingActions(apiDescriptions => apiDescriptions.First());
    options.SwaggerDoc("v1", new OpenApiInfo { Title = "Authentication with JwT and sso", Version = "v1" });
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please enter token",
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        { new OpenApiSecurityScheme { Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer"} }, new string[] {} }
    });
    
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var roles = new[] { "Admin", "Manager", "User" };
    foreach (var role in roles)
    {
        if (!await roleManager.RoleExistsAsync(role))
            await roleManager.CreateAsync(new IdentityRole(role));
    }
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseIdentityServer();
app.UseAuthentication();
app.UseAuthorization();

// Use session middleware
app.UseSession();
app.UseEndpoints(endpoints =>
{
    app.MapControllers();
});

app.Run();
