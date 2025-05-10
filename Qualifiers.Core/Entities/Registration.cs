namespace Qualifiers.Core.Entities;

public class Registration
{
    public int Id { get; set; }
    public string UserId { get; set; }
    public ApplicationUser User { get; set; } = null!;
    public int TimeSlotId { get; set; }
    public TimeSlot TimeSlot { get; set; } = null!;
    public int SeatNumber { get; set; }
    public DateTime RegisteredAt { get; set; } = DateTime.UtcNow;
}