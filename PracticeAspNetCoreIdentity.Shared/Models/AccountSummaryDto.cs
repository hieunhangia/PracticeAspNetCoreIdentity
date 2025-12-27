namespace PracticeAspNetCoreIdentity.Shared.Models;

public class AccountSummaryDto
{
    public Guid Id { get; set; }
    public string? Email { get; set; }
    public bool BanStatus { get; set; }
}