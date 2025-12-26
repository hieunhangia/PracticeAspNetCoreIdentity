using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PracticeAspNetCoreIdentity.Server.Models;
using PracticeAspNetCoreIdentity.Shared.Constants;
using PracticeAspNetCoreIdentity.Shared.Models;

namespace PracticeAspNetCoreIdentity.Server.Controllers;

[ApiController]
[Route("accounts")]
[Authorize(Roles = UserRole.Administrator)]
public class AccountManagementController(UserManager<CustomUser> userManager, AppDbContext context) : ControllerBase
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
            AccountOrderBy.LockedOutAsc => users.OrderBy(u => u.LockoutEnd),
            AccountOrderBy.LockedOutDesc => users.OrderByDescending(u => u.LockoutEnd),
            _ => users.OrderBy(u => u.Email)
        };
        return Ok(await users
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(user => new AccountSummaryDto
            {
                Id = user.Id,
                Email = user.Email,
                LockedOut = user.LockoutEnd != null && user.LockoutEnd > DateTimeOffset.Now
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
                LockoutEnabled =  user.LockoutEnabled,
                AccessFailedCount =  user.AccessFailedCount,
                LockoutEnd = user.LockoutEnd
            })
            : NotFound();
    }

    [HttpPatch("lockout/{id:guid}")]
    public async Task<IActionResult> LockoutAccountAsync(Guid id, [FromBody] long lockoutTimeInSecond)
    {
        var user = await userManager.FindByIdAsync(id.ToString());
        if (user == null) return NotFound();

        if (lockoutTimeInSecond < 0) lockoutTimeInSecond = 0;

        await using var transaction = await context.Database.BeginTransactionAsync();
        var lockOutResult =
            await userManager.SetLockoutEndDateAsync(user, DateTimeOffset.Now.AddSeconds(lockoutTimeInSecond));
        if (!lockOutResult.Succeeded) return BadRequest(lockOutResult.Errors);

        var updateResult = await userManager.UpdateSecurityStampAsync(user);
        if (!updateResult.Succeeded) return BadRequest(updateResult.Errors);

        await transaction.CommitAsync();
        return NoContent();
    }

    [HttpPatch("unlock/{id:guid}")]
    public async Task<IActionResult> UnlockAccountAsync(Guid id)
    {
        var user = await userManager.FindByIdAsync(id.ToString());
        if (user == null) return NotFound();

        var result = await userManager.SetLockoutEndDateAsync(user, null);
        if (!result.Succeeded) return BadRequest(result.Errors);
        return NoContent();
    }
}