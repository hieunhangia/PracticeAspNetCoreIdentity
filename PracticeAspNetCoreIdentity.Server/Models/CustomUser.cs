using Microsoft.AspNetCore.Identity;

namespace PracticeAspNetCoreIdentity.Server.Models;

public class CustomUser : IdentityUser<Guid>
{
    public DateTime CreatedDate { get; set; } = DateTime.UtcNow;
    public bool IsBannable { get; set; } = true;
    public DateTimeOffset? BanEnd { get; set; }

    public ICollection<UserNote>? UserNotes { get; set; }
}