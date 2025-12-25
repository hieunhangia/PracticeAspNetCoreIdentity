using System.Net.Http.Json;

namespace PracticeAspNetCoreIdentity.Client;

public class WebApiHttpClient(HttpClient client)
{
    public async Task<HttpResponseMessage> CookieLoginAsync(string email, string password)
        => await client.PostAsJsonAsync("login?useCookies=true", new { email, password });

    public async Task<HttpResponseMessage> RegisterAsync(string email, string password)
        => await client.PostAsJsonAsync("register", new { email, password });

    public async Task<HttpResponseMessage> GetUserInfoAsync()
        => await client.GetAsync("manage/info");

    public async Task CookieLogoutAsync()
        => await client.PostAsync("cookie-logout", null);

    public async Task<HttpResponseMessage> GetUserRolesAsync()
        => await client.GetAsync("roles");
}