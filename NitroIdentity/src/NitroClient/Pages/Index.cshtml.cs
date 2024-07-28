using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using NitroClient.Infra;

namespace NitroClient.Pages;

public class IndexModel : PageModel
{
    private readonly ILogger<IndexModel> _logger;
    private readonly IdentityCred _identity;
    public IndexModel(ILogger<IndexModel> logger, IdentityCred identity)
    {
        _logger = logger;
        _identity = identity;
    }

    //public async Task<IActionResult> OnGet()
    //{
    //    var token  = await _identity.CallApiOne();

    //    return new JsonResult(token);
    //}

    public void OnGet()
    {

    }
}
