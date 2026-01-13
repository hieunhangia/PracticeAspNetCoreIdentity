namespace PracticeAspNetCoreIdentity.Shared.Models.Identity;

public class SetPasswordRequest
{
    public required string NewPassword { get; init; }
}