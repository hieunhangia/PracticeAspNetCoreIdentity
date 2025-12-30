namespace PracticeAspNetCoreIdentity.Shared.Models.AccountManagement;

public class AccountDetailDto
{
    public Guid Id { get; set; }
    public string? Email { get; set; }
    public bool EmailConfirmed { get; set; }
}