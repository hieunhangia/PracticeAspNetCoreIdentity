namespace PracticeAspNetCoreIdentity.Shared.Models.AccountManagement;

public class AccountDetailDto
{
    public required Guid Id { get; init; }
    public required string Email { get; init; }
    public required bool EmailConfirmed { get; init; }
    public required List<string> AssignedRoles { get; init; }
}