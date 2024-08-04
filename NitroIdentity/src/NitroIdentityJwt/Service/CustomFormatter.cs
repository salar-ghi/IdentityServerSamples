using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.Net.Http.Headers;
using System.Text;

namespace NitroIdentityJwt.Service;

public class CustomFormatter : TextOutputFormatter
{
    public CustomFormatter()
    {
        //SupportedMediaTypes.Add(MediaTypeHeaderValue.Parse("application/vnd.custom+json"));
        SupportedMediaTypes.Add(MediaTypeHeaderValue.Parse("application/plain.text"));
        SupportedEncodings.Add(Encoding.UTF8);
    }

    protected override bool CanWriteType(Type type)
    {
        // Specify the types that this formatter can handle
        return true; // Modify this logic as needed
    }

    public override async Task WriteResponseBodyAsync(OutputFormatterWriteContext context, Encoding selectedEncoding)
    {
        var response = context.HttpContext.Response;

        // Serialize the object to your desired format (e.g., JSON)
        var json = SerializeToJson(context.Object);
        await response.WriteAsync(json, selectedEncoding);
    }

    private string SerializeToJson(object obj)
    {
        // Implement your serialization logic here
        return Newtonsoft.Json.JsonConvert.SerializeObject(obj); // Example using Newtonsoft.Json
    }
}
