using Microsoft.AspNetCore.Identity;

namespace PracticeAspNetCoreIdentity.Server.Models;

public class CustomUser : IdentityUser<Guid>
{
    public string? FullName { get; set; }
}