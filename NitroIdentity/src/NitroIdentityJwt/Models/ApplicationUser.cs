using Microsoft.AspNetCore.Identity;

namespace NitroIdentityJwt.Models;

public class ApplicationUser : IdentityUser
{
    public string NationalId { get; set; }
    public string PostalCode { get; set; }
    public string BourseCode { get; set; }

    public string RefreshToken { get; set; }
    public DateTime RefreshTokenExpiryTime { get; set; }
}
