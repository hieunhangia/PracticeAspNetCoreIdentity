using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using PracticeAspNetCoreIdentity.Server.Models;

namespace PracticeAspNetCoreIdentity.Server.Identity.TokenProviders;

public class CustomPasswordResetTokenProvider(
    IDataProtectionProvider dataProtectionProvider,
    IOptions<PasswordResetTokenProviderOptions> options,
    ILogger<DataProtectorTokenProvider<AppUser>> logger)
    : DataProtectorTokenProvider<AppUser>(dataProtectionProvider, options, logger);

public class PasswordResetTokenProviderOptions : DataProtectionTokenProviderOptions
{
    public PasswordResetTokenProviderOptions()
    {
        Name = "PasswordResetDataProtectorTokenProvider";
        TokenLifespan = TimeSpan.FromMinutes(Constants.TokenExpiredTime.PasswordResetCodeMinutes);
    }
}