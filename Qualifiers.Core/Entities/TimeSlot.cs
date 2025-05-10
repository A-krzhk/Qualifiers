namespace Qualifiers.Core.Entities;

public class TimeSlot
{
    public int Id { get; set; }
    public int DirectionId { get; set; }
    public Direction Direction { get; set; } = null!;
    public DateTime StartTime { get; set; }
    public DateTime EndTime { get; set; }
    public int MaxParticipants { get; set; }
    
    public ICollection<Registration> Registrations { get; set; } = new List<Registration>();
    
    public bool HasAvailableSeats()
    {
        return Registrations.Count < MaxParticipants;
    }
    
    public int GetNextAvailableSeatNumber()
    {
        if (!HasAvailableSeats())
            throw new InvalidOperationException("Нет доступных мест");
                
        var takenSeats = Registrations.Select(r => r.SeatNumber).OrderBy(n => n).ToList();
        
        int seatNumber = 1;
        foreach (var seat in takenSeats)
        {
            if (seat > seatNumber)
                return seatNumber;
            seatNumber = seat + 1;
        }
            
        return seatNumber;
    }
}