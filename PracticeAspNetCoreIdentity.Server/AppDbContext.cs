using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PracticeAspNetCoreIdentity.Server.Models;

namespace PracticeAspNetCoreIdentity.Server;

public class AppDbContext(DbContextOptions<AppDbContext> options) : IdentityDbContext<CustomUser, IdentityRole<Guid>, Guid>(options)
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        ConfigureIdentityTablesName(modelBuilder);
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