namespace PracticeAspNetCoreIdentity.Shared.Models.Identity;

public class UserInfoResponse
{
    public required string Email { get; init; }
    public required bool IsEmailConfirmed { get; init; }
    public required List<string> Roles { get; init; }
}