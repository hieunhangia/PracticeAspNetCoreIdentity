using Microsoft.AspNetCore.Identity;

namespace PracticeAspNetCoreIdentity.Server.Models;

public class CustomUser : IdentityUser<Guid>
{
    public bool BanEnabled { get; set; }
    public DateTimeOffset? BanEnd { get; set; }

    public ICollection<UserNote>? UserNotes { get; set; }
}