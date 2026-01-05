namespace PracticeAspNetCoreIdentity.Client.Identity;

public interface IAccountManagement
{
    Task<ApiResult> CookieLoginAsync(string email, string password);
    Task<ApiResult> CookieGoogleLoginAsync(string idToken);
    Task<ApiResult> RegisterAsync(string email, string password);
    Task<ApiResult> CookieLogoutAsync();
    Task<ApiResult> SendConfirmationEmailAsync(string email);
    Task<ApiResult> ForgotPasswordAsync(string email);
    Task<ApiResult> ResetPasswordAsync(string email, string resetCode, string newPassword);
    Task<ApiResult> ChangePasswordAsync(string oldPassword, string newPassword);
    Task<ApiResult> SetPasswordAsync(string newPassword);
}