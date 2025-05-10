using Microsoft.EntityFrameworkCore;
using Qualifiers.Core.Entities;

namespace Qualifiers.Core.Interfaces;

public interface IApplicationDbContext
{
    DbSet<ApplicationUser> Users { get; }
    DbSet<Direction> Directions { get; }
    DbSet<TimeSlot> TimeSlots { get; }
    DbSet<Registration> Registrations { get; }
        
    Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
}