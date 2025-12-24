using PracticeAspNetCoreIdentity.Client.Identity.Models;

namespace PracticeAspNetCoreIdentity.Client.Identity;

public interface IAccountManagement
{
    Task<FormResult> LoginAsync(string email, string password);
    Task<FormResult> RegisterAsync(string email, string password);
    Task LogoutAsync();
}