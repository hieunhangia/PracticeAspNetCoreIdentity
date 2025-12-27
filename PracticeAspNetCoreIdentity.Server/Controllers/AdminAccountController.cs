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
            AccountOrderBy.BanAsc => users.OrderBy(u => u.LockoutEnd),
            AccountOrderBy.BanDesc => users.OrderByDescending(u => u.LockoutEnd),
            _ => users.OrderBy(u => u.Email)
        };
        return Ok(await users
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(user => new AccountSummaryDto
            {
                Id = user.Id,
                Email = user.Email,
                BanStatus = user.BanEnabled && user.BanEnd > DateTimeOffset.Now
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
    public async Task<IActionResult> LockoutAccountAsync(Guid id, [FromBody] BanUserRequest request)
    {
        var user = await userManager.FindByIdAsync(id.ToString());
        if (user == null) return NotFound();

        if (!user.BanEnabled) return BadRequest("This account cannot be banned.");

        user.BanEnd = DateTimeOffset.Now.AddSeconds(request.BanTimeInSeconds);
        await userManager.UpdateAsync(user);
        await userManager.UpdateSecurityStampAsync(user);
        await cache.SetStringAsync(
            $"banned_{user.Id}",
            "banned",
            new DistributedCacheEntryOptions { AbsoluteExpiration = user.BanEnd }
        );
        return NoContent();
    }

    [HttpPost("{id:guid}/unban")]
    public async Task<IActionResult> UnlockAccountAsync(Guid id)
    {
        var user = await userManager.FindByIdAsync(id.ToString());
        if (user == null) return NotFound();

        if (user.BanEnd == null || user.BanEnd <= DateTimeOffset.Now)
            return BadRequest("This account is not currently banned.");

        user.BanEnd = null;
        await userManager.UpdateAsync(user);
        await cache.RemoveAsync($"banned_{user.Id}");
        return NoContent();
    }
}