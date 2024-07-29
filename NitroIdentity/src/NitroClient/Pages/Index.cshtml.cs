using Microsoft.AspNetCore.Mvc.RazorPages;

namespace NitroClient.Pages;

public class IndexModel : PageModel
{
    private readonly ILogger<IndexModel> _logger;
    public IndexModel(ILogger<IndexModel> logger)
    {
        _logger = logger;
        //_identity = identity;
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
