using PracticeAspNetCoreIdentity.Shared.Constants;
using PracticeAspNetCoreIdentity.Shared.Models.AccountManagement;

namespace PracticeAspNetCoreIdentity.Client.AdminAccountManagement;

public interface IAdminAccountManagement
{
    Task<ApiResult<IEnumerable<AccountSummaryDto>>> GetAllAccountsAsync(int page = 1, int pageSize = 10,
        string orderBy = AccountOrderBy.EmailAsc);

    Task<ApiResult<int>> GetAccountCountAsync();

    Task<ApiResult<AccountDetailDto>> GetAccountByIdAsync(Guid id);
}