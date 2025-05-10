using Qualifiers.Core.DTOs;

namespace Qualifiers.Core.Interfaces;

public interface IAuthService
{
    Task<AuthResponseDTO> RegisterAsync(RegisterDTO registerDto);
    Task<AuthResponseDTO> LoginAsync(LoginDTO loginDto);
}