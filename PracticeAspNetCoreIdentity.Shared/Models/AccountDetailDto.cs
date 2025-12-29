namespace PracticeAspNetCoreIdentity.Shared.Models;

public class AccountDetailDto
{
    public Guid Id { get; set; }
    public string? Email { get; set; }
    public bool EmailConfirmed { get; set; }
    public bool IsBannable { get; set; }
    public DateTimeOffset? BanEnd { get; set; }
}