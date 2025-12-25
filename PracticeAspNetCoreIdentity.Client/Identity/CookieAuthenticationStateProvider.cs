using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Components.Authorization;
using PracticeAspNetCoreIdentity.Client.Identity.Models;

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

        var roles = await rolesResponse.Content.ReadFromJsonAsync<RoleClaim[]>();
        if (roles != null)
            claims.AddRange(roles
                .Where(role => !string.IsNullOrEmpty(role.Type) && !string.IsNullOrEmpty(role.Value))
                .Select(role => new Claim(role.Type, role.Value, role.ValueType, role.Issuer, role.OriginalIssuer)));

        return new AuthenticationState(
            new ClaimsPrincipal(new ClaimsIdentity(claims, nameof(CookieAuthenticationStateProvider))));
    }

    public async Task<FormResult> LoginAsync(string email, string password)
    {
        using var response = await webApiHttpClient.CookieLoginAsync(email, password);
        if (!response.IsSuccessStatusCode)
            return new FormResult
            {
                Succeeded = false,
                ErrorList = ["Invalid email or password."]
            };
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        return new FormResult { Succeeded = true };
    }

    public async Task<FormResult> RegisterAsync(string email, string password)
    {
        using var response = await webApiHttpClient.RegisterAsync(email, password);
        if (response.IsSuccessStatusCode) return new FormResult { Succeeded = true };

        return new FormResult
        {
            Succeeded = false,
            ErrorList = JsonDocument.Parse(await response.Content.ReadAsStringAsync())
                .RootElement.GetProperty("errors").EnumerateObject()
                .SelectMany(x => x.Value.EnumerateArray())
                .Select(x => x.GetString())
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .ToArray()!
        };
    }

    public async Task LogoutAsync()
    {
        await webApiHttpClient.CookieLogoutAsync();
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }
}