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
public class AccountManagementController(UserManager<CustomUser> userManager) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> GetAllAccountsAsync([FromQuery] int page = 1, [FromQuery] int pageSize = 10,
        [FromQuery] string orderBy = AccountOrderBy.EmailAsc)
    {
        if (page < 1) page = 1;
        if (pageSize is < 1 or > 100) pageSize = 10;
        var users = userManager.Users.AsNoTracking();
        users = orderBy switch
        {
            AccountOrderBy.EmailAsc => users.OrderBy(u => u.Email),
            AccountOrderBy.EmailDesc => users.OrderByDescending(u => u.Email),
            _ => users.OrderBy(u => u.Email)
        };
        return Ok(await users
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(user => new AccountSummaryDto
            {
                Id = user.Id,
                Email = user.Email
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
                EmailConfirmed = user.EmailConfirmed
            })
            : NotFound();
    }
}