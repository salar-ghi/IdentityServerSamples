﻿namespace NitroIdentityJwt.Dtos;

public class RegisterDto
{
    public string NationalId { get; set; }
    public string PostalCode { get; set; }
    public string BourseCode { get; set; }
    public string Email { get; set; }
    public string Password { get; set; }
}
