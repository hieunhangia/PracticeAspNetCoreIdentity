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
        using var response = await webApiHttpClient.GetUserInfoAsync();
        if (!response.IsSuccessStatusCode) return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));

        var userInfo = await response.Content.ReadFromJsonAsync<UserInfo>();
        if (userInfo == null) return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));

        var claims = new List<Claim>
        {
            new(ClaimTypes.Name, userInfo.Email),
            new(ClaimTypes.Email, userInfo.Email),
        };
        claims.AddRange(userInfo.Claims
            .Where(c => c.Key != ClaimTypes.Name)
            .Select(c => new Claim(c.Key, c.Value)));

        // In a real application, you might also fetch roles or other claims here.

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