using System.Net.Http.Json;
using PracticeAspNetCoreIdentity.Client.Identity.Models;

namespace PracticeAspNetCoreIdentity.Client;

public class WebApiHttpClient(HttpClient client)
{
    public async Task<HttpResponseMessage> LoginAsync(string email, string password, bool useCookie = true)
        => await client.PostAsJsonAsync(useCookie ? "login?useCookies=true" : "login", new { email, password });

    public async Task<HttpResponseMessage> RegisterAsync(string email, string password)
        => await client.PostAsJsonAsync("register", new { email, password });

    public async Task<UserInfo?> GetUserInfoAsync()
    {
        using var userResponse = await client.GetAsync("manage/info");
        if (userResponse.IsSuccessStatusCode) return await userResponse.Content.ReadFromJsonAsync<UserInfo>();
        return null;
    }

    public async Task<HttpResponseMessage> CookieLogoutAsync()
        => await client.PostAsync("logout", null);
}