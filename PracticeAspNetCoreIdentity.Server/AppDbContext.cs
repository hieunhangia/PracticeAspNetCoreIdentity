using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PracticeAspNetCoreIdentity.Server.Models;

namespace PracticeAspNetCoreIdentity.Server;

public class AppDbContext(DbContextOptions<AppDbContext> options)
    : IdentityDbContext<CustomUser, IdentityRole<Guid>, Guid>(options)
{
    public DbSet<UserNote> UserNotes { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        ConfigureIdentityTablesName(modelBuilder);

        modelBuilder.Entity<CustomUser>(entity => { entity.Property(e => e.BanEnabled).HasDefaultValue(true); });

        modelBuilder.Entity<UserNote>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Name).IsRequired().HasMaxLength(100);
            entity.Property(e => e.Content).IsRequired();
            entity.HasOne(e => e.User)
                .WithMany(u => u.UserNotes)
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }

    private static void ConfigureIdentityTablesName(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<CustomUser>(b => b.ToTable("Users"));
        modelBuilder.Entity<IdentityUserClaim<Guid>>(b => b.ToTable("UserClaims"));
        modelBuilder.Entity<IdentityUserLogin<Guid>>(b => b.ToTable("UserLogins"));
        modelBuilder.Entity<IdentityUserToken<Guid>>(b => b.ToTable("UserTokens"));
        modelBuilder.Entity<IdentityRole<Guid>>(b => b.ToTable("Roles"));
        modelBuilder.Entity<IdentityRoleClaim<Guid>>(b => b.ToTable("RoleClaims"));
        modelBuilder.Entity<IdentityUserRole<Guid>>(b => b.ToTable("UserRoles"));
    }
}