﻿namespace NitroIdentityJwt.Dtos;

public class RefreshTokenDto
{
    public string NationalId { get; set; }
    public string Email { get; set; }
    public string RefreshToken { get; set; }
}
