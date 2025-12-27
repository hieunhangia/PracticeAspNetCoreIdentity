using PracticeAspNetCoreIdentity.Client.Identity.Models;

namespace PracticeAspNetCoreIdentity.Client.Identity;

public interface IAccountManagement
{
    Task<ApiResult> CookieLoginAsync(string email, string password);
    Task<ApiResult> RegisterAsync(string email, string password);
    Task<ApiResult> CookieLogoutAsync();
    Task<ApiResult> ResendConfirmationEmailAsync(string email);
    Task<ApiResult> ForgotPasswordAsync(string email);
    Task<ApiResult> ResetPasswordAsync(string email, string resetCode, string newPassword);
}