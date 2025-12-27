using PracticeAspNetCoreIdentity.Client.Identity.Models;

namespace PracticeAspNetCoreIdentity.Client.Identity;

public interface IAccountManagement
{
    Task<ApiResult> CookieLoginAsync(string email, string password);
    Task<ApiResult> RegisterAsync(string email, string password);
    Task<ApiResult> CookieLogoutAsync();
}