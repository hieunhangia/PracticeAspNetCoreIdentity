using Microsoft.AspNetCore.Identity;
using PracticeAspNetCoreIdentity.Server.Constants;
using PracticeAspNetCoreIdentity.Server.Models;

namespace PracticeAspNetCoreIdentity.Server;

public static class SeedData
{
    private static readonly string[] roles = [UserRole.Administrator, UserRole.Manager, UserRole.User];

    public static async Task InitializeAsync(IServiceProvider serviceProvider, IConfiguration configuration)
    {
        await using var dbContext = serviceProvider.GetRequiredService<AppDbContext>();
        await dbContext.Database.EnsureCreatedAsync();
        
        using var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();
        using var userManager = serviceProvider.GetRequiredService<UserManager<CustomUser>>();
        
        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role)) await roleManager.CreateAsync(new IdentityRole<Guid>(role));
        }

        var adminEmail = configuration["AdminEmail"]!;
        if (await userManager.FindByEmailAsync(adminEmail) == null)
        {
            var adminUser = new CustomUser
            {
                UserName = adminEmail, 
                Email = adminEmail
            };
            var result = await userManager.CreateAsync(adminUser, configuration["AdminPassword"]!);
            if (result.Succeeded) await userManager.AddToRolesAsync(adminUser, roles);
        }
    }
    
    public static async Task EnsureDeletedAsync(IServiceProvider serviceProvider)
    {
        await using var dbContext = serviceProvider.GetRequiredService<AppDbContext>();
        await dbContext.Database.EnsureDeletedAsync();
    }
}