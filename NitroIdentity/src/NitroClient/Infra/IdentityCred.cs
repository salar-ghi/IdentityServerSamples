using IdentityModel.Client;
using System.Text.Json;

namespace NitroClient.Infra;

public class IdentityCred
{
    private readonly HttpClient _client;
    public IdentityCred(HttpClient client)
    {
        _client = client;
    }


    public async Task<string> RequestTokenFromServer()
    {
        // discover endpoints from metadata
        var disco = await _client.GetDiscoveryDocumentAsync("https://localhost:5001");
        if (disco.IsError)
        {
            Console.WriteLine(disco.Error);
            return disco.IsError.ToString();
        }

        // request token
        var tokenResponse = await _client.RequestClientCredentialsTokenAsync(new ClientCredentialsTokenRequest
        {
            Address = disco.TokenEndpoint,
            ClientId = "m2m.client",
            //ClientSecret = "511536EF-F270-4058-80CA-1C89C192F69A",
            ClientSecret = "secret",
            //Scope = "scope1"
            Scope = "api1"
        });

        if (tokenResponse.IsError)
        {
            Console.WriteLine(tokenResponse.Error);
            Console.WriteLine(tokenResponse.ErrorDescription);
            return tokenResponse.IsError.ToString();
        }
        var accessTokenResponse = tokenResponse.AccessToken;
        Console.WriteLine(tokenResponse.AccessToken);
        return accessTokenResponse;
    }


    public async Task<string> CallApiOne()
    {
        var accessToken = await RequestTokenFromServer();
        _client.SetBearerToken(accessToken);

        var response = await _client.GetAsync("https://localhost:6001/api/Products");
        if (!response.IsSuccessStatusCode)
        {
            Console.WriteLine(response.StatusCode);
            return response.StatusCode.ToString();
        }
        else
        {
            var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
            Console.WriteLine(JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true }));
            var accessTokenResponse = JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
            return accessTokenResponse;
        }
    }
}
