using Microsoft.EntityFrameworkCore;
using Qualifiers.Core.Entities;
using Qualifiers.Core.Interfaces;

namespace Qualifiers.Core.Services;

public class RegistrationService
    {
        private readonly IApplicationDbContext _context;
        
        public RegistrationService(IApplicationDbContext context)
        {
            _context = context;
        }
        
        public async Task<RegistrationDto> RegisterForTimeSlotAsync(string userId, int timeSlotId)
        {
            var user = await _context.Users.FindAsync(userId);
            if (user == null)
                throw new KeyNotFoundException("Пользователь не найден");
            
            var timeSlot = await _context.TimeSlots
                .Include(ts => ts.Direction)
                .Include(ts => ts.Registrations)
                .FirstOrDefaultAsync(ts => ts.Id == timeSlotId);
                
            if (timeSlot == null)
                throw new KeyNotFoundException("Временной интервал не найден");
            
            if (!timeSlot.HasAvailableSeats())
                throw new InvalidOperationException("Свободных мест на это время нет");
            
            var existingRegistration = await _context.Registrations
                .Include(r => r.TimeSlot)
                .AnyAsync(r => r.UserId == userId && 
                               r.TimeSlot.DirectionId == timeSlot.DirectionId);
                               
            if (existingRegistration)
                throw new InvalidOperationException("Вы уже зарегистрированы на это направление");
            
            var seatNumber = timeSlot.GetNextAvailableSeatNumber();
            
            var registration = new Registration
            {
                UserId = userId,
                TimeSlotId = timeSlotId,
                SeatNumber = seatNumber,
                RegisteredAt = DateTime.UtcNow
            };
            
            _context.Registrations.Add(registration);
            await _context.SaveChangesAsync();
            
            return new RegistrationDto
            {
                Id = registration.Id,
                DirectionName = timeSlot.Direction.Name,
                StartTime = timeSlot.StartTime,
                EndTime = timeSlot.EndTime,
                SeatNumber = seatNumber
            };
        }
        
        public async Task CancelRegistrationAsync(string userId, int registrationId)
        {
            var registration = await _context.Registrations
                .FirstOrDefaultAsync(r => r.Id == registrationId && r.UserId == userId);
                
            if (registration == null)
                throw new KeyNotFoundException("Запись не найдена");
                
            _context.Registrations.Remove(registration);
            await _context.SaveChangesAsync();
        }
        
        public async Task<IEnumerable<RegistrationDto>> GetUserRegistrationsAsync(string userId)
        {
            var registrations = await _context.Registrations
                .Include(r => r.TimeSlot)
                .ThenInclude(ts => ts.Direction)
                .Where(r => r.UserId == userId)
                .Select(r => new RegistrationDto
                {
                    Id = r.Id,
                    DirectionName = r.TimeSlot.Direction.Name,
                    StartTime = r.TimeSlot.StartTime,
                    EndTime = r.TimeSlot.EndTime,
                    SeatNumber = r.SeatNumber
                })
                .ToListAsync();
                
            return registrations;
        }
        
        public async Task<ParticipantDto> GetParticipantByNumberAsync(int timeSlotId, int seatNumber)
        {
            var registration = await _context.Registrations
                .Include(r => r.User)
                .FirstOrDefaultAsync(r => r.TimeSlotId == timeSlotId && r.SeatNumber == seatNumber);
                
            if (registration == null)
                throw new KeyNotFoundException("Участник не найден");
                
            return new ParticipantDto
            {
                FullName = string.Format("{0} {1}", registration.User.FirstName, registration.User.LastName),
                Email = registration.User.Email,
                TelegramUsername = registration.User.Telegram,
                SeatNumber = registration.SeatNumber
            };
        }
    }
    
    public class RegistrationDto
    {
        public int Id { get; set; }
        public string DirectionName { get; set; } = string.Empty;
        public DateTime StartTime { get; set; }
        public DateTime EndTime { get; set; }
        public int SeatNumber { get; set; }
    }
    
    public class ParticipantDto
    {
        public string FullName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string TelegramUsername { get; set; } = string.Empty;
        public int SeatNumber { get; set; }
    }