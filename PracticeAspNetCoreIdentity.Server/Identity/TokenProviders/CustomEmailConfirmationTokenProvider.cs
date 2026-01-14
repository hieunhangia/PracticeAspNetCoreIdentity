using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using PracticeAspNetCoreIdentity.Server.Models;

namespace PracticeAspNetCoreIdentity.Server.Identity.TokenProviders;

public class CustomEmailConfirmationTokenProvider(
    IDataProtectionProvider dataProtectionProvider,
    IOptions<EmailConfirmationTokenProviderOptions> options,
    ILogger<DataProtectorTokenProvider<AppUser>> logger)
    : DataProtectorTokenProvider<AppUser>(dataProtectionProvider, options, logger);

public class EmailConfirmationTokenProviderOptions : DataProtectionTokenProviderOptions
{
    public EmailConfirmationTokenProviderOptions()
    {
        Name = "EmailDataProtectorTokenProvider";
        TokenLifespan = TimeSpan.FromHours(Constants.TokenExpiredTime.EmailConfirmationHours);
    }
}