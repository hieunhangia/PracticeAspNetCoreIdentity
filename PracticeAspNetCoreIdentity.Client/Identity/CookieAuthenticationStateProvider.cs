using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Components.Authorization;
using PracticeAspNetCoreIdentity.Client.Identity.Models;
using PracticeAspNetCoreIdentity.Shared.Models.Identity;

namespace PracticeAspNetCoreIdentity.Client.Identity;

public class CookieAuthenticationStateProvider(WebApiHttpClient webApiHttpClient)
    : AuthenticationStateProvider, IAccountManagement
{
    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        using var userResponse = await webApiHttpClient.GetUserInfoAsync();
        if (!userResponse.IsSuccessStatusCode)
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));

        var userInfo = await userResponse.Content.ReadFromJsonAsync<UserInfo>();
        if (userInfo == null) return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, userInfo.Email),
            new(ClaimTypes.Email, userInfo.Email),
        };
        claims.AddRange(userInfo.Claims
            .Where(c => c.Key != ClaimTypes.Name)
            .Select(c => new Claim(c.Key, c.Value)));

        using var rolesResponse = await webApiHttpClient.GetUserRolesAsync();

        if (!rolesResponse.IsSuccessStatusCode)
            return new AuthenticationState(
                new ClaimsPrincipal(new ClaimsIdentity(claims, nameof(CookieAuthenticationStateProvider))));

        var roles = await rolesResponse.Content.ReadFromJsonAsync<string[]>();
        if (roles != null)
            claims.AddRange(roles
                .Where(role => !string.IsNullOrWhiteSpace(role))
                .Select(role => new Claim(ClaimTypes.Role, role)));

        return new AuthenticationState(
            new ClaimsPrincipal(new ClaimsIdentity(claims, nameof(CookieAuthenticationStateProvider))));
    }

    public async Task<ApiResult> CookieLoginAsync(string email, string password)
    {
        using var response = await webApiHttpClient.CookieLoginAsync(email, password);
        if (!response.IsSuccessStatusCode)
            return new ApiResult
            {
                Succeeded = false,
                ErrorList = ["Login failed. Please check your credentials and try again."]
            };
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        return new ApiResult { Succeeded = true };
    }

    public async Task<ApiResult> CookieGoogleLoginAsync(string idToken)
    {
        using var response =
            await webApiHttpClient.CookieGoogleLoginAsync(new GoogleLoginRequest { IdToken = idToken });
        if (!response.IsSuccessStatusCode)
            return new ApiResult
            {
                Succeeded = false,
                ErrorList = ["Google login failed. Please try again."]
            };
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        return new ApiResult { Succeeded = true };
    }

    public async Task<ApiResult> RegisterAsync(string email, string password)
    {
        using var response = await webApiHttpClient.RegisterAsync(email, password);
        if (response.IsSuccessStatusCode) return new ApiResult { Succeeded = true };

        var content = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(content);
        var errors = doc.RootElement.GetProperty("errors").EnumerateObject()
            .SelectMany(entry =>
            {
                return entry.Value.ValueKind switch
                {
                    JsonValueKind.Array => entry.Value.EnumerateArray().Select(e => e.GetString()),
                    JsonValueKind.String => [entry.Value.GetString()],
                    _ => []
                };
            })
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .ToList();

        return new ApiResult
        {
            Succeeded = false,
            ErrorList = errors!
        };
    }

    public async Task<ApiResult> CookieLogoutAsync()
    {
        using var response = await webApiHttpClient.CookieLogoutAsync();
        if (!response.IsSuccessStatusCode)
        {
            return new ApiResult
            {
                Succeeded = false,
                ErrorList = ["Logout failed."]
            };
        }

        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        return new ApiResult { Succeeded = true };
    }

    public async Task<ApiResult> ResendConfirmationEmailAsync(string email)
    {
        using var response = await webApiHttpClient.ResendConfirmationEmailAsync(email);
        if (response.IsSuccessStatusCode) return new ApiResult { Succeeded = true };

        return new ApiResult
        {
            Succeeded = false,
            ErrorList = ["Failed to resend confirmation email."]
        };
    }

    public async Task<ApiResult> ForgotPasswordAsync(string email)
    {
        using var response = await webApiHttpClient.ForgotPasswordAsync(email);
        if (response.IsSuccessStatusCode) return new ApiResult { Succeeded = true };

        return new ApiResult
        {
            Succeeded = false,
            ErrorList = ["Failed to send password reset email."]
        };
    }

    public async Task<ApiResult> ResetPasswordAsync(string email, string resetCode, string newPassword)
    {
        using var response = await webApiHttpClient.ResetPasswordAsync(email, resetCode, newPassword);
        if (response.IsSuccessStatusCode) return new ApiResult { Succeeded = true };

        var content = await response.Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(content);
        var errors = doc.RootElement.GetProperty("errors").EnumerateObject()
            .SelectMany(entry =>
            {
                return entry.Value.ValueKind switch
                {
                    JsonValueKind.Array => entry.Value.EnumerateArray().Select(e => e.GetString()),
                    JsonValueKind.String => [entry.Value.GetString()],
                    _ => []
                };
            })
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .ToList();

        return new ApiResult
        {
            Succeeded = false,
            ErrorList = errors!
        };
    }
}