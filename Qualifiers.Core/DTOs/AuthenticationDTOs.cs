using System.ComponentModel.DataAnnotations;

namespace Qualifiers.Core.DTOs;

public class RegisterDTO
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    [StringLength(100, MinimumLength = 6)]
    public string Password { get; set; }

    [Required]
    [Compare("Password")]
    public string ConfirmPassword { get; set; }

    [Required]
    public string FirstName { get; set; }

    [Required]
    public string LastName { get; set; }
    
    [Required]
    public string Role { get; set; }
    
    [Required]
    public string Telegram { get; set; }
}

public class LoginDTO
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    public string Password { get; set; }
}

public class AuthResponseDTO
{
    public bool IsSuccess { get; set; }
    public string Message { get; set; }
    public string Token { get; set; }
    public string RefreshToken { get; set; }
    public DateTime? Expiration { get; set; }
}
