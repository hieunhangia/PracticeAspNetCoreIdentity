using Microsoft.EntityFrameworkCore;

namespace PracticeAspNetCoreIdentity.Server.Identity.BackgroundServices;

public class CleanupUnconfirmEmailAccountService(
    IServiceScopeFactory scopeFactory,
    ILogger<CleanupUnconfirmEmailAccountService> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer =
            new PeriodicTimer(TimeSpan.FromHours(Constants.BackgroundServiceInterval
                .CleanupUnconfirmEmailAccountServiceHours));

        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            using var scope = scopeFactory.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();

            var deletedCount = await dbContext.Users
                .Where(u => !u.EmailConfirmed && u.CreatedDate <
                    DateTime.UtcNow.AddHours(-Constants.TokenExpiredTime.EmailConfirmationHours))
                .ExecuteDeleteAsync(stoppingToken);

            if (deletedCount <= 0) continue;
            if (logger.IsEnabled(LogLevel.Information))
                logger.LogInformation("Deleted {DeletedCount} unconfirmed email accounts.", deletedCount);
        }
    }
}