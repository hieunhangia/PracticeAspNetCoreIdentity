using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Caching.Distributed;

namespace PracticeAspNetCoreIdentity.Server.Identity;

public class CustomBanMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context, IDistributedCache cache)
    {
        if (context.User.Identity is { IsAuthenticated: true })
        {
            var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);

            var isBanned = await cache.GetStringAsync($"banned_{userId}");

            if (!string.IsNullOrEmpty(isBanned))
            {
                await context.SignOutAsync(IdentityConstants.ApplicationScheme);
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }
        }

        await next(context);
    }
}