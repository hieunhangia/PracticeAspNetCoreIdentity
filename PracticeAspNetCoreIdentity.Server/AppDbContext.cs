using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using PracticeAspNetCoreIdentity.Server.Models;

namespace PracticeAspNetCoreIdentity.Server;

public class AppDbContext(DbContextOptions<AppDbContext> options) : IdentityDbContext<CustomUser, IdentityRole<Guid>, Guid>(options);