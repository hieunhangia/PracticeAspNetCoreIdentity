namespace PracticeAspNetCoreIdentity.Shared.Models.AccountManagement;

public class UserInfoResponse
{
    public required string Email { get; init; }
    public required bool IsEmailConfirmed { get; init; }
}