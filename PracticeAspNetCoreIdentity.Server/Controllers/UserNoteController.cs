using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PracticeAspNetCoreIdentity.Server.Models;
using PracticeAspNetCoreIdentity.Shared.Models;

namespace PracticeAspNetCoreIdentity.Server.Controllers;

[ApiController]
[Route("notes")]
[Authorize]
public class UserNoteController(AppDbContext context) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> GetUserNotesAsync()
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var userNote = await context.UserNotes
            .Where(u => u.UserId == userId)
            .Select(u => new UserNoteDto
            {
                Id = u.Id,
                Name = u.Name,
                Content = u.Content
            })
            .ToListAsync();
        return Ok(userNote);
    }

    [HttpGet]
    [Route("{id:guid}")]
    public async Task<IActionResult> GetUserNoteByIdAsync(Guid id)
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var userNote = await context.UserNotes
            .Where(u => u.UserId == userId && u.Id == id)
            .Select(u => new UserNoteDto
            {
                Id = u.Id,
                Name = u.Name,
                Content = u.Content
            })
            .FirstOrDefaultAsync();
        return userNote != null ? Ok(userNote) : NotFound();
    }

    [HttpPost]
    public async Task<IActionResult> AddUserNoteAsync([FromBody] CreateUpdateUserNoteRequest request)
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var userNote = new UserNote { UserId = userId, Name = request.Name!, Content = request.Content! };
        context.UserNotes.Add(userNote);
        await context.SaveChangesAsync();
        return CreatedAtAction("GetUserNoteById", new { id = userNote.Id }, userNote);
    }

    [HttpPut]
    [Route("{id:guid}")]
    public async Task<IActionResult> UpdateUserNoteAsync(Guid id, [FromBody] CreateUpdateUserNoteRequest request)
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var userNote = await context.UserNotes
            .FirstOrDefaultAsync(u => u.UserId == userId && u.Id == id);
        if (userNote == null) return NotFound();
        userNote.Name = request.Name!;
        userNote.Content = request.Content!;
        await context.SaveChangesAsync();
        return NoContent();
    }

    [HttpDelete]
    [Route("{id:guid}")]
    public async Task<IActionResult> DeleteUserNoteAsync(Guid id)
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var userNote = await context.UserNotes
            .FirstOrDefaultAsync(u => u.UserId == userId && u.Id == id);
        if (userNote == null) return NotFound();
        context.UserNotes.Remove(userNote);
        await context.SaveChangesAsync();
        return NoContent();
    }
}