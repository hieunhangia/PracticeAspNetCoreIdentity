using PracticeAspNetCoreIdentity.Shared.Constants;
using PracticeAspNetCoreIdentity.Shared.Models;
using PracticeAspNetCoreIdentity.Shared.Models.AccountManagement;

namespace PracticeAspNetCoreIdentity.Client.AdminAccountManagement;

public interface IAdminAccountManagement
{
    Task<ApiResult<PagedResultDto<AccountSummaryDto>>> GetAllAccountsAsync(int page = 1, int pageSize = 10,
        string orderBy = AccountOrderBy.EmailAsc);

    Task<ApiResult<AccountDetailDto>> GetAccountDetailByIdAsync(Guid id);
}