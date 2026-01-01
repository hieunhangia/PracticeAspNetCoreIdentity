namespace PracticeAspNetCoreIdentity.Shared.Models.AccountManagement;

public class AccountSummaryDto
{
    public required Guid Id { get; init; }
    public required string Email { get; init; }
}