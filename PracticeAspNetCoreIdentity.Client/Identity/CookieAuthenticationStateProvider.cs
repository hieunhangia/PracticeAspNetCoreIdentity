using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
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

        var userInfo = await userResponse.Content.ReadFromJsonAsync<UserInfoDto>();
        if (userInfo == null) return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, userInfo.Email),
            new(ClaimTypes.Email, userInfo.Email),
        };

        using var rolesResponse = await webApiHttpClient.GetUserRolesAsync();

        if (!rolesResponse.IsSuccessStatusCode)
            return new AuthenticationState(
                new ClaimsPrincipal(new ClaimsIdentity(claims, nameof(CookieAuthenticationStateProvider))));

        var roles = await rolesResponse.Content.ReadFromJsonAsync<RolesDto>();
        if (roles is { Roles: not null })
            claims.AddRange(roles.Roles
                .Where(role => !string.IsNullOrWhiteSpace(role))
                .Select(role => new Claim(ClaimTypes.Role, role)));

        return new AuthenticationState(
            new ClaimsPrincipal(new ClaimsIdentity(claims, nameof(CookieAuthenticationStateProvider))));
    }

    public async Task<ApiResult> CookieLoginAsync(string email, string password)
    {
        using var response = await webApiHttpClient.CookieLoginAsync(email, password);
        if (!response.IsSuccessStatusCode)
            return ApiResult.Failure((await response.Content.ReadFromJsonAsync<ApiValidationProblemDetails>())?
                .Errors?.Values.SelectMany(x => x).ToList() ?? []);
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        return ApiResult.Success();
    }

    public async Task<ApiResult> CookieGoogleLoginAsync(string idToken)
    {
        using var response =
            await webApiHttpClient.CookieGoogleLoginAsync(new GoogleLoginRequest { IdToken = idToken });
        if (!response.IsSuccessStatusCode)
            return ApiResult.Failure((await response.Content.ReadFromJsonAsync<ApiValidationProblemDetails>())?
                .Errors?.Values.SelectMany(x => x).ToList() ?? []);
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        return ApiResult.Success();
    }

    public async Task<ApiResult> RegisterAsync(string email, string password)
    {
        using var response = await webApiHttpClient.RegisterAsync(email, password);
        return response.IsSuccessStatusCode
            ? ApiResult.Success()
            : ApiResult.Failure((await response.Content.ReadFromJsonAsync<ApiValidationProblemDetails>())?
                .Errors?.Values.SelectMany(x => x).ToList() ?? []);
    }

    public async Task<ApiResult> CookieLogoutAsync()
    {
        using var response = await webApiHttpClient.CookieLogoutAsync();
        if (!response.IsSuccessStatusCode) return ApiResult.Failure("Logout failed.");
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        return ApiResult.Success();
    }

    public async Task<ApiResult> SendConfirmationEmailAsync(string email)
    {
        using var response = await webApiHttpClient.SendConfirmationEmailAsync(email);
        return response.IsSuccessStatusCode
            ? ApiResult.Success()
            : ApiResult.Failure("Failed to send confirmation email.");
    }

    public async Task<ApiResult> ForgotPasswordAsync(string email)
    {
        using var response = await webApiHttpClient.ForgotPasswordAsync(email);
        return response.IsSuccessStatusCode
            ? ApiResult.Success()
            : ApiResult.Failure("Failed to process forgot password request.");
    }

    public async Task<ApiResult> ResetPasswordAsync(string email, string resetCode, string newPassword)
    {
        using var response = await webApiHttpClient.ResetPasswordAsync(email, resetCode, newPassword);
        return response.IsSuccessStatusCode
            ? ApiResult.Success()
            : ApiResult.Failure((await response.Content.ReadFromJsonAsync<ApiValidationProblemDetails>())?
                .Errors?.Values.SelectMany(x => x).ToList() ?? []);
    }
}