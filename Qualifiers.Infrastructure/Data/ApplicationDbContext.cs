using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Qualifiers.Core.Entities;
using Qualifiers.Core.Interfaces;

namespace Qualifiers.Infrastructure.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>, IApplicationDbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }
        
        public DbSet<ApplicationUser> Users => Set<ApplicationUser>();
        public DbSet<Direction> Directions => Set<Direction>();
        public DbSet<TimeSlot> TimeSlots => Set<TimeSlot>();
        public DbSet<Registration> Registrations => Set<Registration>();
        
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<Direction>()
                .HasOne(d => d.CreatedBy)
                .WithMany()
                .HasForeignKey(d => d.CreatedById)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<TimeSlot>()
                .HasOne(ts => ts.Direction)
                .WithMany(d => d.TimeSlots)
                .HasForeignKey(ts => ts.DirectionId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<Registration>()
                .HasOne(r => r.User)
                .WithMany(u => u.Registrations)
                .HasForeignKey(r => r.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<Registration>()
                .HasOne(r => r.TimeSlot)
                .WithMany(ts => ts.Registrations)
                .HasForeignKey(r => r.TimeSlotId)
                .OnDelete(DeleteBehavior.Cascade);

            modelBuilder.Entity<Registration>()
                .HasIndex(r => new { r.TimeSlotId, r.SeatNumber })
                .IsUnique();

            modelBuilder.Entity<Registration>()
                .HasIndex(r => new { r.UserId, r.TimeSlotId }) 
                .IsUnique();
        }
    }