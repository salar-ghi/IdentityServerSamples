using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Net.Http.Headers;
using System.Text.Json;

namespace MyApp.Namespace;

//public class CallApiModel : PageModel
//{
//    IHttpClientFactory httpClientFactory;
//    public string Json = string.Empty;
//    //public async Task OnGet()
//    //{
//    //    var accessToken = await HttpContext.GetTokenAsync("access_token");
//    //    var client = new HttpClient();

//    //    client.DefaultRequestHeaders.Authorization =
//    //        new AuthenticationHeaderValue("Bearer", accessToken);
//    //    var content = await client.GetStringAsync("https://localhost:6001/api/Products");
//    //    var parsed = JsonDocument.Parse(content);
//    //    var formatted = JsonSerializer.Serialize(parsed, new JsonSerializerOptions
//    //    {
//    //        WriteIndented = true,                
//    //    });
//    //    Json = formatted;
//    //}


//    public async Task OnGet()
//    {
//        var tokenInfo = await HttpContext.GetUserAccessTokenAsync();
//        //var client = new HttpClient();
//        using HttpClient client = httpClientFactory.CreateClient();
//        client.SetBearerToken(tokenInfo.AccessToken!);

//        //var content = await client.GetStringAsync("https://localhost:6001/identity");
//        var content = await client.GetStringAsync("https://localhost:6001/api/Products");

//        var parsed = JsonDocument.Parse(content);
//        var formatted = JsonSerializer.Serialize(parsed, new JsonSerializerOptions { WriteIndented = true });

//        Json = formatted;
//    }
//}


public class CallApiModel(IHttpClientFactory httpClientFactory) : PageModel
{
    public string Json = string.Empty;

    public async Task OnGet()
    {
        using var client = httpClientFactory.CreateClient("apiClient");

        var content = await client.GetStringAsync("https://localhost:6001/identity");

        var parsed = JsonDocument.Parse(content);
        var formatted = JsonSerializer.Serialize(parsed, new JsonSerializerOptions { WriteIndented = true });

        Json = formatted;
    }
}
