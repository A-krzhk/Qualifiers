using Microsoft.EntityFrameworkCore;
using Qualifiers.Core.Entities;
using Qualifiers.Core.Interfaces;

namespace Qualifiers.Core.Services;

public class DirectionService
    {
        private readonly IApplicationDbContext _context;
        
        public DirectionService(IApplicationDbContext context)
        {
            _context = context;
        }
        
        public async Task<IEnumerable<DirectionDto>> GetAllDirectionsAsync()
        {
            var directions = await _context.Directions
                .Include(d => d.TimeSlots)
                .Select(d => new DirectionDto
                {
                    Id = d.Id,
                    Name = d.Name,
                    Description = d.Description,
                    TimeSlots = d.TimeSlots.Select(ts => new TimeSlotDto
                    {
                        Id = ts.Id,
                        StartTime = ts.StartTime,
                        EndTime = ts.EndTime,
                        MaxParticipants = ts.MaxParticipants,
                        AvailableSeats = ts.MaxParticipants - ts.Registrations.Count
                    }).ToList()
                })
                .ToListAsync();
                
            return directions;
        }
        
        public async Task<DirectionDto> CreateDirectionAsync(CreateDirectionRequest request, string userId)
        {
            // Проверка существования пользователя
            var userExists = await _context.Users.AnyAsync(u => u.Id == userId);
            if (!userExists)
            {
                throw new ArgumentException($"User with ID {userId} does not exist.");
            }

            var direction = new Direction
            {
                Name = request.Name,
                Description = request.Description,
                CreatedById = userId,
                CreatedAt = DateTime.UtcNow
            };
    
            _context.Directions.Add(direction);
            await _context.SaveChangesAsync();
    
            return new DirectionDto
            {
                Id = direction.Id,
                Name = direction.Name,
                Description = direction.Description,
                TimeSlots = new List<TimeSlotDto>()
            };
        }
        
        public async Task<TimeSlotDto> AddTimeSlotAsync(int directionId, CreateTimeSlotRequest request)
        {
            var direction = await _context.Directions.FindAsync(directionId);
            if (direction == null)
                throw new KeyNotFoundException("Направление не найдено");
                
            var timeSlot = new TimeSlot
            {
                DirectionId = directionId,
                StartTime = request.StartTime,
                EndTime = request.EndTime,
                MaxParticipants = request.MaxParticipants
            };
            
            _context.TimeSlots.Add(timeSlot);
            await _context.SaveChangesAsync();
            
            return new TimeSlotDto
            {
                Id = timeSlot.Id,
                StartTime = timeSlot.StartTime,
                EndTime = timeSlot.EndTime,
                MaxParticipants = timeSlot.MaxParticipants,
                AvailableSeats = timeSlot.MaxParticipants
            };
        }
        
        public async Task DeleteDirectionAsync(int directionId)
        {
            var direction = await _context.Directions
                .FirstOrDefaultAsync(d => d.Id == directionId);
        
            if (direction == null)
                throw new KeyNotFoundException("Направление не найдено");

            _context.Directions.Remove(direction);
            await _context.SaveChangesAsync();
        }
    }


        
    public class DirectionDto
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public List<TimeSlotDto> TimeSlots { get; set; } = new List<TimeSlotDto>();
    }
    
    public class TimeSlotDto
    {
        public int Id { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public int MaxParticipants { get; set; }
        public int AvailableSeats { get; set; }
    }
    
    public class CreateDirectionRequest
    {
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
    }
    
    public class CreateTimeSlotRequest
    {
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public int MaxParticipants { get; set; }
    }