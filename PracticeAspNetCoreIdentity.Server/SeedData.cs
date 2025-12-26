using Microsoft.AspNetCore.Identity;
using PracticeAspNetCoreIdentity.Server.Models;
using PracticeAspNetCoreIdentity.Shared.Constants;

namespace PracticeAspNetCoreIdentity.Server;

public static class SeedData
{
    private static readonly string[] roles = [UserRole.Administrator, UserRole.Manager, UserRole.User];

    private static readonly (string Email, string Password, bool LockoutEnabled, string[] Roles)[] users =
    [
        (
            "admin@app.com",
            "Admin@123",
            false,
            [UserRole.Administrator, UserRole.Manager, UserRole.User]
        ),
        (
            "manager@app.com",
            "Manager@123",
            true,
            [UserRole.Manager, UserRole.User]
        ),
        (
            "user@app.com",
            "User@123",
            true,
            [UserRole.User]
        )
    ];

    public static async Task InitializeAsync(IServiceProvider appService, bool dropExistDatabase = false)
    {
        using var scope = appService.CreateScope();
        var scopeService = scope.ServiceProvider;

        await using var dbContext = scopeService.GetRequiredService<AppDbContext>();

        if (dropExistDatabase) await dbContext.Database.EnsureDeletedAsync();

        await dbContext.Database.EnsureCreatedAsync();

        var roleManager = scopeService.GetRequiredService<RoleManager<IdentityRole<Guid>>>();
        var userManager = scopeService.GetRequiredService<UserManager<CustomUser>>();

        await using var transaction = await dbContext.Database.BeginTransactionAsync();
        foreach (var role in roles)
        {
            if (await roleManager.RoleExistsAsync(role)) continue;
            var roleResult = await roleManager.CreateAsync(new IdentityRole<Guid>(role));
            if (!roleResult.Succeeded)
                throw new Exception($"Create roles failed: {FormatIdentityErrors(roleResult.Errors)}");
        }

        foreach (var userData in users)
        {
            if (await userManager.FindByEmailAsync(userData.Email) != null) continue;

            var user = new CustomUser
            {
                UserName = userData.Email,
                Email = userData.Email
            };
            var userResult = await userManager.CreateAsync(user, userData.Password);
            if (!userResult.Succeeded)
                throw new Exception($"Create user failed: {FormatIdentityErrors(userResult.Errors)}");

            var lockoutResult = await userManager.SetLockoutEnabledAsync(user, userData.LockoutEnabled);
            if (!lockoutResult.Succeeded)
                throw new Exception($"Set lockout enabled failed: {FormatIdentityErrors(lockoutResult.Errors)}");

            var userRoleResult = await userManager.AddToRolesAsync(user, userData.Roles);
            if (!userRoleResult.Succeeded)
                throw new Exception($"Add roles to user failed: {FormatIdentityErrors(userRoleResult.Errors)}");
        }

        await transaction.CommitAsync();
        return;

        static string FormatIdentityErrors(IEnumerable<IdentityError> errors)
        {
            return string.Join(", ", errors.Select(e => $"{e.Code}: {e.Description}"));
        }
    }
}