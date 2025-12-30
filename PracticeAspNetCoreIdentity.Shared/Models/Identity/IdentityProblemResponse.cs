namespace PracticeAspNetCoreIdentity.Shared.Models.Identity;

public class IdentityProblemResponse
{
    public Dictionary<string, string[]>? Errors { get; set; }
}