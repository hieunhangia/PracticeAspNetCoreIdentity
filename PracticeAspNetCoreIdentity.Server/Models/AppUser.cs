using Microsoft.AspNetCore.Identity;

namespace PracticeAspNetCoreIdentity.Server.Models;

public class AppUser : IdentityUser<Guid>
{
    public DateTime CreatedDate { get; set; } = DateTime.UtcNow;

    public ICollection<UserNote>? UserNotes { get; set; }
}