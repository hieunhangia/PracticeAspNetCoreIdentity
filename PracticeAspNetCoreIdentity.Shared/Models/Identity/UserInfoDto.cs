namespace PracticeAspNetCoreIdentity.Shared.Models.Identity;

public class UserInfoDto
{
    public string Email { get; set; } = string.Empty;
    public bool IsEmailConfirmed { get; set; }
}