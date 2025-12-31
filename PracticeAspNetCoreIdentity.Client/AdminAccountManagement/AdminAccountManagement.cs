using PracticeAspNetCoreIdentity.Shared.Constants;
using PracticeAspNetCoreIdentity.Shared.Models.AccountManagement;

namespace PracticeAspNetCoreIdentity.Client.AdminAccountManagement;

public class AdminAccountManagement(WebApiHttpClient webApiHttpClient) : IAdminAccountManagement
{
    public Task<ApiResult<IEnumerable<AccountSummaryDto>>> GetAllAccountsAsync(int page = 1, int pageSize = 10,
        string orderBy = AccountOrderBy.EmailAsc) => webApiHttpClient.GetAllAccountsAsync(page, pageSize, orderBy);

    public Task<ApiResult<int>> GetAccountCountAsync() => webApiHttpClient.GetAccountCountAsync();

    public Task<ApiResult<AccountDetailDto>> GetAccountByIdAsync(Guid id) => webApiHttpClient.GetAccountByIdAsync(id);
}