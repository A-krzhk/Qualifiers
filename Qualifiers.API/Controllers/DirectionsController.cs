using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Qualifiers.Core.Constants;
using Qualifiers.Core.Services;

namespace kursovaya.Controllers;

[ApiController]
[Route("api/[controller]")]
public class   DirectionsController: ControllerBase
{
    private readonly DirectionService _directionService;
            
    public DirectionsController(DirectionService directionService)
    {
        _directionService = directionService;
    }
        
    [HttpGet]
    public async Task<ActionResult<IEnumerable<DirectionDto>>> GetAllDirections()
    {
        var directions = await _directionService.GetAllDirectionsAsync();
        return Ok(directions);
    }
        
    [HttpPost]
    [Authorize(Roles = RoleConstants.Staff)]
    public async Task<ActionResult<DirectionDto>> CreateDirection(CreateDirectionRequest request)
    {
        var userId = User.FindFirstValue("uid"); 
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized("User ID not found in token.");
        }
        var direction = await _directionService.CreateDirectionAsync(request, userId);
        return CreatedAtAction(nameof(GetAllDirections), new { id = direction.Id }, direction);
    }
            
    [HttpPost("{directionId}/timeslots")]
    [Authorize(Roles = RoleConstants.Staff)]
    public async Task<ActionResult<TimeSlotDto>> AddTimeSlot(int directionId, CreateTimeSlotRequest request)
    {
        try
        {
            var timeSlot = await _directionService.AddTimeSlotAsync(directionId, request);
            return Ok(timeSlot);
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(ex.Message);
        }
    }
    
    [HttpDelete("{directionId}")]
    [Authorize(Roles = RoleConstants.Staff)]
    public async Task<IActionResult> DeleteDirection(int directionId)
    {
        try
        {
            await _directionService.DeleteDirectionAsync(directionId);
            return NoContent();
        }
        catch (KeyNotFoundException ex)
        {
            return NotFound(ex.Message);
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"An error occurred while deleting the direction: {ex.Message}");
        }
    }
}