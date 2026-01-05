using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using PracticeAspNetCoreIdentity.Shared.Constants;
using PracticeAspNetCoreIdentity.Shared.Models.Identity;

namespace PracticeAspNetCoreIdentity.Client.Identity;

public class CookieAuthenticationStateProvider(WebApiHttpClient webApiHttpClient)
    : AuthenticationStateProvider, IAccountManagement
{
    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var userInfoResult = await webApiHttpClient.GetUserInfoAsync();
        if (!userInfoResult.Succeeded || userInfoResult.Data == null)
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, userInfoResult.Data.Email),
            new(ClaimTypes.Email, userInfoResult.Data.Email),
            new(CustomClaimTypes.EmailConfirmed, userInfoResult.Data.EmailConfirmed.ToString()),
            new(CustomClaimTypes.HasPassword, userInfoResult.Data.HasPassword.ToString())
        };

        claims.AddRange(userInfoResult.Data.Roles
            .Where(role => !string.IsNullOrWhiteSpace(role))
            .Select(role => new Claim(ClaimTypes.Role, role)));

        return new AuthenticationState(
            new ClaimsPrincipal(new ClaimsIdentity(claims, nameof(CookieAuthenticationStateProvider))));
    }

    public async Task<ApiResult> CookieLoginAsync(string email, string password)
    {
        var result = await webApiHttpClient.CookieLoginAsync(email, password);
        if (result.Succeeded) NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        return result;
    }

    public async Task<ApiResult> CookieGoogleLoginAsync(string idToken)
    {
        var result = await webApiHttpClient.CookieGoogleLoginAsync(new GoogleLoginRequest { IdToken = idToken });
        if (result.Succeeded) NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        return result;
    }

    public async Task<ApiResult> RegisterAsync(string email, string password) =>
        await webApiHttpClient.RegisterAsync(email, password);

    public async Task<ApiResult> CookieLogoutAsync()
    {
        var result = await webApiHttpClient.CookieLogoutAsync();
        if (result.Succeeded) NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        return result;
    }

    public async Task<ApiResult> SendConfirmationEmailAsync(string email) =>
        await webApiHttpClient.SendConfirmationEmailAsync(email);

    public async Task<ApiResult> ForgotPasswordAsync(string email) => await webApiHttpClient.ForgotPasswordAsync(email);

    public async Task<ApiResult> ResetPasswordAsync(string email, string resetCode, string newPassword) =>
        await webApiHttpClient.ResetPasswordAsync(email, resetCode, newPassword);

    public Task<ApiResult> ChangePasswordAsync(string oldPassword, string newPassword) =>
        webApiHttpClient.ChangePasswordAsync(oldPassword, newPassword);

    public async Task<ApiResult> SetPasswordAsync(string newPassword)
    {
        var result = await webApiHttpClient.SetPasswordAsync(newPassword);
        if (result.Succeeded) NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        return result;
    }
}