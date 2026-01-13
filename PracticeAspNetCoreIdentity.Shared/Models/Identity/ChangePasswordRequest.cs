namespace PracticeAspNetCoreIdentity.Shared.Models.Identity;

public class ChangePasswordRequest
{
    public required string OldPassword { get; init; }
    public required string NewPassword { get; init; }
}