using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Qualifiers.Core.Constants;
using Qualifiers.Core.Services;

namespace kursovaya.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class RegistrationsController : ControllerBase
{
    private readonly RegistrationService _registrationService;
    
    public RegistrationsController(RegistrationService registrationService)
    {
        _registrationService = registrationService;
    }
    
    [HttpGet("my")]
    public async Task<ActionResult<IEnumerable<RegistrationDto>>> GetMyRegistrations()
    {
        var userId = User.FindFirstValue("uid");
        var registrations = await _registrationService.GetUserRegistrationsAsync(userId);
        return Ok(registrations);
    }
    
    [HttpPost("timeslot/{timeSlotId}")]
    public async Task<ActionResult<RegistrationDto>> RegisterForTimeSlot(int timeSlotId)
    {
        var userId = User.FindFirstValue("uid");
        
        try
        {
            var registration = await _registrationService.RegisterForTimeSlotAsync(userId, timeSlotId);
            return Ok(registration);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(ex.Message);
        }
    }
    
    [HttpDelete("{registrationId}")]
    public async Task<ActionResult> CancelRegistration(int registrationId)
    {
        var userId = User.FindFirstValue("uid");
        
        try
        {
            await _registrationService.CancelRegistrationAsync(userId, registrationId);
            return NoContent();
        }
        catch (KeyNotFoundException)
        {
            return NotFound("Registration not found");
        }
    }
    
    [HttpGet("timeslot/{timeSlotId}/participant/{seatNumber}")]
    [Authorize(Roles = RoleConstants.Staff)]
    public async Task<ActionResult<ParticipantDto>> GetParticipantByNumber(int timeSlotId, int seatNumber)
    {
        try
        {
            var participant = await _registrationService.GetParticipantByNumberAsync(timeSlotId, seatNumber);
            return Ok(participant);
        }
        catch (KeyNotFoundException)
        {
            return NotFound("Participant not found");
        }
    }
}