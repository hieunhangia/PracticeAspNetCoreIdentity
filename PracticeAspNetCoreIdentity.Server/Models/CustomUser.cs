using Microsoft.AspNetCore.Identity;

namespace PracticeAspNetCoreIdentity.Server.Models;

public class CustomUser : IdentityUser<Guid>
{
    public ICollection<UserNote>? UserNotes { get; set; }
}