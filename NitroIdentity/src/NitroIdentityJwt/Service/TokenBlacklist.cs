namespace NitroIdentityJwt.Service;

public class TokenBlacklist
{
    private static HashSet<string> _blacklistedTokens = new HashSet<string>();

    public static void BlacklistToken(string token)
    {
        _blacklistedTokens.Add(token);
    }

    public static bool IsBlacklisted(string token)
    {
        return _blacklistedTokens.Contains(token);
    }
}
