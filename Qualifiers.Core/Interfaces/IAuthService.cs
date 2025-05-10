using Qualifiers.Core.DTOs;

namespace Qualifiers.Core.Interfaces;

public interface IAuthService
{
    Task<AuthResponseDTO> RegisterAsync(RegisterDTO registerDto);
    Task<AuthResponseDTO> LoginAsync(LoginDTO loginDto);
    Task<AuthResponseDTO> RefreshTokenAsync(RefreshTokenDTO refreshTokenDto);
    Task<bool> RevokeTokenAsync(string username);
}