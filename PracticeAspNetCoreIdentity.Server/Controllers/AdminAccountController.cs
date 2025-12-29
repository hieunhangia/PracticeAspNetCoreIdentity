using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using PracticeAspNetCoreIdentity.Server.Models;
using PracticeAspNetCoreIdentity.Shared.Constants;
using PracticeAspNetCoreIdentity.Shared.Models;

namespace PracticeAspNetCoreIdentity.Server.Controllers;

[ApiController]
[Route("accounts")]
[Authorize(Roles = UserRole.Administrator)]
public class AccountManagementController(UserManager<CustomUser> userManager, IDistributedCache cache) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> GetAllAccountsAsync([FromQuery] int page = 1, [FromQuery] int pageSize = 10,
        [FromQuery] string orderBy = AccountOrderBy.EmailAsc)
    {
        if (page < 1) page = 1;
        if (pageSize is < 1 or > 1000) pageSize = 10;
        var users = userManager.Users;
        users = orderBy switch
        {
            AccountOrderBy.EmailAsc => users.OrderBy(u => u.Email),
            AccountOrderBy.EmailDesc => users.OrderByDescending(u => u.Email),
            AccountOrderBy.BanStatusAsc => users.OrderBy(u => u.BanEnabled),
            AccountOrderBy.BanStatusDesc => users.OrderByDescending(u => u.BanEnabled),
            _ => users.OrderBy(u => u.Email)
        };
        return Ok(await users
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(user => new AccountSummaryDto
            {
                Id = user.Id,
                Email = user.Email,
                BanStatus = user.BanEnabled && user.BanEnd > DateTimeOffset.UtcNow
            })
            .ToListAsync());
    }

    [HttpGet("count")]
    public async Task<IActionResult> GetAccountCountAsync() => Ok(await userManager.Users.CountAsync());

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> GetAccountByIdAsync(Guid id)
    {
        var user = await userManager.FindByIdAsync(id.ToString());
        return user != null
            ? Ok(new AccountDetailDto
            {
                Id = user.Id,
                Email = user.Email,
                EmailConfirmed = user.EmailConfirmed,
                BanEnabled = user.BanEnabled,
                BanEnd = user.BanEnd
            })
            : NotFound();
    }

    [HttpPost("{id:guid}/ban")]
    public async Task<IActionResult> BanAccountAsync(Guid id, [FromBody] BanUserRequest request)
    {
        var user = await userManager.FindByIdAsync(id.ToString());
        if (user == null) return NotFound();

        if (!user.BanEnabled) return BadRequest("This account cannot be banned.");

        user.BanEnd = DateTimeOffset.UtcNow.AddSeconds(request.BanTimeInSeconds);
        user.SecurityStamp = Guid.NewGuid().ToString();
        var result = await userManager.UpdateAsync(user);
        if (!result.Succeeded) return BadRequest("Failed to ban the account.");

        await cache.SetStringAsync($"banned_{user.Id}", "banned",
            new DistributedCacheEntryOptions { AbsoluteExpiration = user.BanEnd }
        );

        return NoContent();
    }

    [HttpPost("{id:guid}/unban")]
    public async Task<IActionResult> UnbanAccountAsync(Guid id)
    {
        var user = await userManager.FindByIdAsync(id.ToString());
        if (user == null) return NotFound();

        if (user.BanEnd == null || user.BanEnd <= DateTimeOffset.UtcNow)
            return BadRequest("This account is not currently banned.");

        user.BanEnd = null;
        var result = await userManager.UpdateAsync(user);
        if (!result.Succeeded) return BadRequest("Failed to unban the account.");

        await cache.RemoveAsync($"banned_{user.Id}");

        return NoContent();
    }
}