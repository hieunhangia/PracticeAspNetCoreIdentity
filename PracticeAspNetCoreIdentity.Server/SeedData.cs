using Microsoft.AspNetCore.Identity;
using PracticeAspNetCoreIdentity.Server.Models;
using PracticeAspNetCoreIdentity.Shared.Constants;

namespace PracticeAspNetCoreIdentity.Server;

public static class SeedData
{
    private static readonly string[] roles = [UserRole.Administrator, UserRole.Manager, UserRole.User];

    private static readonly (CustomUser user, string password, string[] roles)[] users =
    [
        (
            new CustomUser
            {
                UserName = "admin@app.com",
                Email = "admin@app.com",
                LockoutEnabled = false
            },
            "Admin@36",
            [UserRole.Administrator, UserRole.Manager, UserRole.User]
        ),
        (
            new CustomUser
            {
                UserName = "manager@app.com",
                Email = "manager@app.com"
            },
            "Manager@36",
            [UserRole.Manager, UserRole.User]
        ),
        (
            new CustomUser
            {
                UserName = "user@app.com",
                Email = "user@app.com",
            },
            "User@36",
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

        foreach (var user in users)
        {
            if (await userManager.FindByEmailAsync(user.user.Email!) != null) continue;

            var userResult = await userManager.CreateAsync(user.user, user.password);
            if (!userResult.Succeeded)
                throw new Exception($"Create user failed: {FormatIdentityErrors(userResult.Errors)}");

            var userRoleResult = await userManager.AddToRolesAsync(user.user, user.roles);
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