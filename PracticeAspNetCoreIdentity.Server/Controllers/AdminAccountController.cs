using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PracticeAspNetCoreIdentity.Server.Models;
using PracticeAspNetCoreIdentity.Shared.Constants;
using PracticeAspNetCoreIdentity.Shared.Models;
using PracticeAspNetCoreIdentity.Shared.Models.AccountManagement;

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
            AccountOrderBy.EmailDesc => users.OrderByDescending(u => u.Email),
            _ => users.OrderBy(u => u.Email)
        };
        return Ok(new PagedResultDto<AccountSummaryDto>(await users
            .Skip((page - 1) * pageSize).Take(pageSize)
            .Select(user => new AccountSummaryDto
            {
                Id = user.Id,
                Email = user.Email
            }).ToListAsync(), page, pageSize, orderBy, await users.CountAsync()));
    }

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