using System.Net.Http.Json;
using Flurl;
using PracticeAspNetCoreIdentity.Client.Identity;
using PracticeAspNetCoreIdentity.Shared.Constants;
using PracticeAspNetCoreIdentity.Shared.Models;
using PracticeAspNetCoreIdentity.Shared.Models.AccountManagement;
using PracticeAspNetCoreIdentity.Shared.Models.Identity;
using PracticeAspNetCoreIdentity.Shared.Models.UserNote;

namespace PracticeAspNetCoreIdentity.Client;

public class WebApiHttpClient(HttpClient client)
{
    // Authentication & User Management
    public async Task<ApiResult> CookieLoginAsync(string email, string password) =>
        await ApiResult.CreateAsync(await client.PostAsJsonAsync("login".SetQueryParam("useCookies", "true"),
            new { email, password }));

    public async Task<ApiResult> CookieGoogleLoginAsync(GoogleLoginRequest request) =>
        await ApiResult.CreateAsync(await client.PostAsJsonAsync("google-login".SetQueryParam("useCookies", "true"),
            request));

    public async Task<ApiResult> RegisterAsync(string email, string password) =>
        await ApiResult.CreateAsync(await client.PostAsJsonAsync("register", new { email, password }));

    public async Task<ApiResult> SendConfirmationEmailAsync(string email)
        => await ApiResult.CreateAsync(await client.PostAsJsonAsync("send-confirmation-email", new { email }));

    public async Task<ApiResult> ForgotPasswordAsync(string email) =>
        await ApiResult.CreateAsync(await client.PostAsJsonAsync("forgot-password", new { email }));

    public async Task<ApiResult> ResetPasswordAsync(string email, string resetCode, string newPassword) =>
        await ApiResult.CreateAsync(await client.PostAsJsonAsync("reset-password",
            new { email, resetCode, newPassword }));

    public async Task<ApiResult> ChangePasswordAsync(string oldPassword, string newPassword) =>
        await ApiResult.CreateAsync(await client.PostAsJsonAsync("manage".AppendPathSegment("info"),
            new { oldPassword, newPassword }));

    public async Task<ApiResult<InfoResponse>> GetUserInfoAsync() =>
        await ApiResult.CreateAsync<InfoResponse>(await client.GetAsync("manage".AppendPathSegment("info")));

    public async Task<ApiResult> CookieLogoutAsync() =>
        await ApiResult.CreateAsync(await client.PostAsync("cookie-logout", null));

    public async Task<ApiResult<RolesDto>> GetUserRolesAsync() =>
        await ApiResult.CreateAsync<RolesDto>(await client.GetAsync("manage".AppendPathSegment("roles")));


    // Admin Account Management
    public async Task<ApiResult<PagedResultDto<AccountSummaryDto>>> GetAllAccountsAsync(int page = 1, int pageSize = 10,
        string orderBy = AccountOrderBy.EmailAsc) =>
        await ApiResult.CreateAsync<PagedResultDto<AccountSummaryDto>>(await client.GetAsync($"accounts"
            .SetQueryParam("page", page).SetQueryParam("pageSize", pageSize).SetQueryParam("orderBy", orderBy)));

    public async Task<ApiResult<AccountDetailDto>> GetAccountByIdAsync(Guid id) =>
        await ApiResult.CreateAsync<AccountDetailDto>(await client.GetAsync($"accounts".AppendPathSegment(id)));

    public async Task<ApiResult> AddRolesToAccountAsync(Guid id, AddRolesRequest request) =>
        await ApiResult.CreateAsync(
            await client.PostAsJsonAsync($"accounts".AppendPathSegment(id).AppendPathSegment("roles"), request));

    public async Task<ApiResult> RemoveRolesFromAccountAsync(Guid id, IEnumerable<string> roles) =>
        await ApiResult.CreateAsync(await client.DeleteAsync($"accounts".AppendPathSegment(id)
            .AppendPathSegment("roles").SetQueryParam("roles", roles)));


    // User Notes Management
    public async Task<ApiResult<IEnumerable<UserNoteDto>>> GetAllNotesAsync() =>
        await ApiResult.CreateAsync<IEnumerable<UserNoteDto>>(await client.GetAsync("notes"));

    public async Task<ApiResult<UserNoteDto>> GetNoteByIdAsync(Guid id) =>
        await ApiResult.CreateAsync<UserNoteDto>(await client.GetAsync($"notes".AppendPathSegment(id)));

    public async Task<ApiResult> AddNoteAsync(CreateUpdateUserNoteRequest request) =>
        await ApiResult.CreateAsync(await client.PostAsJsonAsync("notes", request));

    public async Task<ApiResult> UpdateNoteAsync(Guid id, CreateUpdateUserNoteRequest request) =>
        await ApiResult.CreateAsync(await client.PutAsJsonAsync($"notes".AppendPathSegment(id), request));

    public async Task<ApiResult> DeleteNoteAsync(Guid id) =>
        await ApiResult.CreateAsync(await client.DeleteAsync($"notes".AppendPathSegment(id)));
}