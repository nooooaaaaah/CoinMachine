namespace CoinMachine;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

public interface IUser
{
    int UserID{ get; }
    string Username { get; }
    string Role { get; }
}
public interface ITokenService
{
    string GenerateToken(IUser user);
}
public class TokenService : ITokenService
{
    private readonly string _secretKey;
    private readonly string _issuer;
    private readonly int _expiryMinutes;
    private readonly List<string> _roles;

    public TokenService(string secretKey, string issuer, int expiryMinutes, List<string> roles)
    {
        if (secretKey == null || Encoding.UTF8.GetBytes(secretKey).Length < 16)
        {
            throw new ArgumentException("Secret key must be at least 16 bytes long.");
        }
        _secretKey = secretKey;
        _issuer = issuer;
        _expiryMinutes = expiryMinutes;
        _roles = roles;
    }


    public string GenerateToken(IUser user)
    {
        if (user == null || string.IsNullOrEmpty(user.Username) || string.IsNullOrEmpty(user.Role))
        {
            throw new ArgumentException("User, Username, or Role is null or empty.");
        }

        if (!_roles.Contains(user.Role, StringComparer.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Role is not valid.");
        }

        ClaimsIdentity identity = new (new[]
        {
                new Claim(ClaimTypes.NameIdentifier, user.UserID.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, user.Role)
            });

        SecurityTokenDescriptor descriptor = new()
        {
            Subject = identity,
            Expires = DateTime.UtcNow.AddMinutes(_expiryMinutes),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secretKey)), SecurityAlgorithms.HmacSha256Signature),
            Issuer = _issuer,
        };

        JwtSecurityTokenHandler handler = new ();
        SecurityToken token = handler.CreateToken(descriptor);
        return handler.WriteToken(token);
    }
}