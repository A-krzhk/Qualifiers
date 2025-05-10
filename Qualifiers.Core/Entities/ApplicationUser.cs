using Microsoft.AspNetCore.Identity;

namespace Qualifiers.Core.Entities;

public class ApplicationUser : IdentityUser
{
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string Telegram { get; set; } = string.Empty;
    public string RefreshToken { get; set; }
    public DateTime RefreshTokenExpiryTime { get; set; }
}