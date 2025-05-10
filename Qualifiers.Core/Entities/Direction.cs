using System.ComponentModel.DataAnnotations;

namespace Qualifiers.Core.Entities;

public class Direction
{
    [Key]
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string CreatedById { get; set; }
    public ApplicationUser CreatedBy { get; set; } = null!;
    
    public ICollection<TimeSlot> TimeSlots { get; set; } = new List<TimeSlot>();
}