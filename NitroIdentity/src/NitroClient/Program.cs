using NitroClient.Infra;
using Duende.AccessTokenManagement.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

builder.Services.AddHttpClient();
builder.Services.AddServices();
builder.Services.AddOpenIdConnectAccessTokenManagement();
builder.Services.AddUserAccessTokenHttpClient("apiClient", configureClient: client =>
{
    client.BaseAddress = new Uri("https://localhost:6001");
});
//builder.Services.AddSingleton<IdentityCred>();

builder.Services.AddCors();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.Use(async (context, next) =>
{
    context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'; connect-src 'self' http://localhost:50530");
    await next();
});

app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages().RequireAuthorization();


//app.UseEndpoints(endpoints =>
//{
//    endpoints.MapGet("/Identity/Identity", (IdentityCred idcred) =>
//    {
//        return idcred.CallApiOne();
//    });
//});

//app.MapGet("/identity/accessToken", (IdentityCred idcred) =>
//{
//    return idcred.CallApiOne();
//});


app.Run();
