using Microsoft.AspNetCore.Identity;

namespace PracticeAspNetCoreIdentity.Server.Models;

public class CustomUser : IdentityUser
{
    public string? FullName { get; set; }
}