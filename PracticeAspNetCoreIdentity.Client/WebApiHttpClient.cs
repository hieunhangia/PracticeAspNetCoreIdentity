using System.Net.Http.Json;
using PracticeAspNetCoreIdentity.Shared.Constants;
using PracticeAspNetCoreIdentity.Shared.Models.AccountManagement;
using PracticeAspNetCoreIdentity.Shared.Models.Identity;
using PracticeAspNetCoreIdentity.Shared.Models.UserNote;

namespace PracticeAspNetCoreIdentity.Client;

public class WebApiHttpClient(HttpClient client)
{
    // Authentication & User Management
    public async Task<ApiResult> CookieLoginAsync(string email, string password)
        => await ApiResult.CreateAsync(await client.PostAsJsonAsync("login?useCookies=true",
            new { email, password }));

    public async Task<ApiResult> CookieGoogleLoginAsync(GoogleLoginRequest request)
        => await ApiResult.CreateAsync(await client.PostAsJsonAsync("google-login?useCookies=true", request));

    public async Task<ApiResult> RegisterAsync(string email, string password)
        => await ApiResult.CreateAsync(await client.PostAsJsonAsync("register", new { email, password }));

    public async Task<ApiResult> SendConfirmationEmailAsync(string email)
        => await ApiResult.CreateAsync(await client.PostAsJsonAsync("send-confirmation-email", new { email }));

    public async Task<ApiResult> ForgotPasswordAsync(string email)
        => await ApiResult.CreateAsync(await client.PostAsJsonAsync("forgot-password", new { email }));

    public async Task<ApiResult> ResetPasswordAsync(string email, string resetCode, string newPassword)
        => await ApiResult.CreateAsync(await client.PostAsJsonAsync("reset-password",
            new { email, resetCode, newPassword }));

    public async Task<ApiResult> ChangePasswordAsync(string oldPassword, string newPassword)
        => await ApiResult.CreateAsync(await client.PostAsJsonAsync("manage/info", new { oldPassword, newPassword }));

    public async Task<ApiResult<UserInfoDto>> GetUserInfoAsync()
        => await ApiResult.CreateAsync<UserInfoDto>(await client.GetAsync("manage/info"));

    public async Task<ApiResult> CookieLogoutAsync()
        => await ApiResult.CreateAsync(await client.PostAsync("cookie-logout", null));

    public async Task<ApiResult<RolesDto>> GetUserRolesAsync()
        => await ApiResult.CreateAsync<RolesDto>(await client.GetAsync("manage/roles"));


    // Account Management
    public async Task<ApiResult<IEnumerable<AccountSummaryDto>>> GetAllAccountsAsync(int page = 1, int pageSize = 10,
        string orderBy = AccountOrderBy.EmailAsc)
        => await ApiResult.CreateAsync<IEnumerable<AccountSummaryDto>>(
            await client.GetAsync($"accounts?page={page}&pageSize={pageSize}&orderBy={orderBy}"));

    public async Task<ApiResult<int>> GetAccountCountAsync()
        => await ApiResult.CreateAsync<int>(await client.GetAsync("accounts/count"));

    public async Task<ApiResult<AccountDetailDto>> GetAccountByIdAsync(Guid id)
        => await ApiResult.CreateAsync<AccountDetailDto>(await client.GetAsync($"accounts/{id}"));


    // User Notes Management
    public async Task<ApiResult<IEnumerable<UserNoteDto>>> GetAllNotesAsync()
        => await ApiResult.CreateAsync<IEnumerable<UserNoteDto>>(await client.GetAsync("notes"));

    public async Task<ApiResult<UserNoteDto>> GetNoteByIdAsync(Guid id)
        => await ApiResult.CreateAsync<UserNoteDto>(await client.GetAsync($"notes/{id}"));

    public async Task<ApiResult> AddNoteAsync(CreateUpdateUserNoteRequest request)
        => await ApiResult.CreateAsync(await client.PostAsJsonAsync("notes", request));

    public async Task<ApiResult> UpdateNoteAsync(Guid id, CreateUpdateUserNoteRequest request)
        => await ApiResult.CreateAsync(await client.PutAsJsonAsync($"notes/{id}", request));

    public async Task<ApiResult> DeleteNoteAsync(Guid id)
        => await ApiResult.CreateAsync(await client.DeleteAsync($"notes/{id}"));
}