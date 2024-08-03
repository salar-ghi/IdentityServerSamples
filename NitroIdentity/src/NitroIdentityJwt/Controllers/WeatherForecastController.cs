using Duende.IdentityServer.Models;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;

namespace NitroIdentityJwt.Controllers;

[Authorize]
[ApiController]
[Route("api/[controller]")]
public class WeatherForecastController : ControllerBase
{
    private readonly IHttpClientFactory _httpClientFactory;
    public WeatherForecastController(IAuthorizationService authorizationService,
        ILogger<WeatherForecastController> logger,
        IHttpClientFactory httpClientFactory)
    {
        _authorizationService = authorizationService;
        _logger = logger;
        _httpClientFactory = httpClientFactory;
        _client = new HttpClient();
    }

    private readonly HttpClient _client;

    private readonly IAuthorizationService _authorizationService;

    private static readonly string[] Summaries = new[]
    {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

    private readonly ILogger<WeatherForecastController> _logger;

    [HttpGet("some-action")]
    public async Task<IActionResult> SomeAction()
    {
        var result = await _authorizationService.AuthorizeAsync(User, null, "WriteAccess");
        if (!result.Succeeded)
        {
            return Forbid();
        }

        // Proceed with action
        return Ok();
    }

    [HttpGet("GetWeatherForecast")]
    public IEnumerable<WeatherForecast> Get()
    {
        return Enumerable.Range(1, 5).Select(index => new WeatherForecast
        {
            Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            TemperatureC = Random.Shared.Next(-20, 55),
            Summary = Summaries[Random.Shared.Next(Summaries.Length)]
        })
        .ToArray();
    }

    [HttpGet("Index")]
    public async Task<ActionResult<string>> Index()
    {
        var value = HttpContext.Session.GetString("Token");
        return value;
    }

    [HttpGet("admin-only")]
    [Authorize(Roles = "Admin")]
    public IActionResult AdminOnly()
    {
        return Ok("Admin access granted");
    }

    [Authorize(Policy = "WriteAccess")]
    [HttpPost]
    public IActionResult CreateTerm([FromBody] string model)
    {
        // Action logic here
        return Ok();
    }

    [Authorize(Policy = "DeleteAccess")]
    [HttpDelete("{id}")]
    public IActionResult DeleteTerm(int id)
    {
        // Action logic here
        return Ok();
    }


    [HttpGet("ApiTwo")]
    //[Authorize(Roles = "User")]
    public async Task<IActionResult> CallApitwo()
    {
        var Token = HttpContext.Session.GetString("Token");
        if (string.IsNullOrEmpty(Token))
        {
            return Unauthorized("No token found in session.");
        }

        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        HttpContext.Request.Headers["Authorization"] = "Bearer " + Token;
        _client.SetBearerToken(Token);

        var response = await _client.GetAsync("https://localhost:5005/api/Users");
        if (!response.IsSuccessStatusCode)
        {
            Console.WriteLine(response.StatusCode);
            return Unauthorized(response.Content);
        }
        else
        {
            var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;
            Console.WriteLine(JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true }));
            var accessTokenResponse = JsonSerializer.Serialize(doc, new JsonSerializerOptions { WriteIndented = true });
            return Ok(accessTokenResponse);
        }

    }
}
