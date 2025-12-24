using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using PracticeAspNetCoreIdentity.Client.Identity.Models;

namespace PracticeAspNetCoreIdentity.Client.Identity;

public class CookieAuthenticationStateProvider(WebApiHttpClient webApiHttpClient) : AuthenticationStateProvider
{
    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        using var userResponse = await webApiHttpClient.GetUserInfoAsync();
        if (!userResponse.IsSuccessStatusCode) return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        
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

        // In a real application, you might also fetch roles or other claims here.
        
        return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(claims, nameof(CookieAuthenticationStateProvider))));
    }
}