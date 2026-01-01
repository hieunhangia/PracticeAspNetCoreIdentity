namespace PracticeAspNetCoreIdentity.Client.Identity;

public class InfoResponse
{
    public required string Email { get; init; }
    public required bool IsEmailConfirmed { get; init; }
}