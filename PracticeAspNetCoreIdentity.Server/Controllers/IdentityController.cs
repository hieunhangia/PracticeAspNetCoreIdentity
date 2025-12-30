using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Encodings.Web;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using PracticeAspNetCoreIdentity.Server.Models;
using PracticeAspNetCoreIdentity.Shared.Constants;
using PracticeAspNetCoreIdentity.Shared.Models.Identity;

namespace PracticeAspNetCoreIdentity.Server.Controllers;

[ApiController]
public class IdentityController(
    AppDbContext dbContext,
    IConfiguration configuration,
    UserManager<CustomUser> userManager,
    SignInManager<CustomUser> signInManager,
    IUserStore<CustomUser> userStore,
    IEmailSender<CustomUser> emailSender,
    IOptionsMonitor<BearerTokenOptions> bearerTokenOptions,
    TimeProvider timeProvider
) : ControllerBase
{
    // Validate the email address using DataAnnotations like the UserValidator does when RequireUniqueEmail = true.
    private static readonly EmailAddressAttribute _emailAddressAttribute = new();

    private const string ConfirmEmailRouteName = "ConfirmEmailRoute";

    [HttpPost("register")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(IdentityProblemResponse), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest registration)
    {
        if (!userManager.SupportsUserEmail)
            throw new NotSupportedException($"{nameof(IdentityController)} requires a user store with email support.");

        var emailStore = (IUserEmailStore<CustomUser>)userStore;
        var email = registration.Email;

        if (string.IsNullOrEmpty(email) || !_emailAddressAttribute.IsValid(email))
            return BadRequest(CreateIdentityProblemResponse(
                IdentityResult.Failed(userManager.ErrorDescriber.InvalidEmail(email))));

        var user = new CustomUser();
        await userStore.SetUserNameAsync(user, email, CancellationToken.None);
        await emailStore.SetEmailAsync(user, email, CancellationToken.None);

        await using var transaction = await dbContext.Database.BeginTransactionAsync();

        var result = await userManager.CreateAsync(user, registration.Password);
        if (!result.Succeeded) return BadRequest(CreateIdentityProblemResponse(result));

        result = await userManager.AddToRoleAsync(user, UserRole.User);
        if (!result.Succeeded) return BadRequest(CreateIdentityProblemResponse(result));

        await transaction.CommitAsync();
        return Ok();
    }

    [HttpPost("login")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(AccessTokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(IdentityProblemResponse), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Login([FromBody] LoginRequest login, [FromQuery] bool? useCookies,
        [FromQuery] bool? useSessionCookies)
    {
        var useCookieScheme = (useCookies == true) || (useSessionCookies == true);
        var isPersistent = (useCookies == true) && (useSessionCookies != true);
        signInManager.AuthenticationScheme =
            useCookieScheme ? IdentityConstants.ApplicationScheme : IdentityConstants.BearerScheme;

        var result = await signInManager.PasswordSignInAsync(login.Email, login.Password, isPersistent,
            lockoutOnFailure: true);

        if (result.RequiresTwoFactor)
        {
            if (!string.IsNullOrEmpty(login.TwoFactorCode))
                result = await signInManager.TwoFactorAuthenticatorSignInAsync(login.TwoFactorCode, isPersistent,
                    rememberClient: isPersistent);
            else if (!string.IsNullOrEmpty(login.TwoFactorRecoveryCode))
                result = await signInManager.TwoFactorRecoveryCodeSignInAsync(login.TwoFactorRecoveryCode);
        }

        if (result.IsLockedOut)
            return BadRequest(CreateIdentityProblemResponse("TooManyFailedLoginAttempts",
                "Too many failed login attempts have occurred. Please try again later."));

        if (!result.Succeeded)
            return BadRequest(CreateIdentityProblemResponse("InvalidLogin",
                "The provided login credentials are invalid. Please check your email and password and try again."));

        // The signInManager already produced the needed response in the form of a cookie or bearer token.
        return Ok();
    }

    [HttpPost("cookie-google-login")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(IdentityProblemResponse), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> CookieGoogleLogin([FromBody] GoogleLoginRequest request)
    {
        try
        {
            var payload = await GoogleJsonWebSignature.ValidateAsync(request.IdToken,
                new GoogleJsonWebSignature.ValidationSettings { Audience = [configuration["GoogleClientId"]] });

            if (!payload.EmailVerified)
                return BadRequest(CreateIdentityProblemResponse("UnverifiedEmail",
                    "The email address is not verified by Google and cannot be used to log in."));

            var user = await userManager.FindByLoginAsync(Identity.Constants.LoginProvider.Google, payload.Subject);
            if (user == null)
            {
                user = await userManager.FindByEmailAsync(payload.Email);
                if (user == null)
                {
                    var emailStore = (IUserEmailStore<CustomUser>)userStore;
                    user = new CustomUser
                    {
                        UserName = payload.Email,
                        Email = payload.Email,
                        EmailConfirmed = true
                    };

                    await userStore.SetUserNameAsync(user, payload.Email, CancellationToken.None);
                    await emailStore.SetEmailAsync(user, payload.Email, CancellationToken.None);

                    await using var transaction = await dbContext.Database.BeginTransactionAsync();

                    var result = await userManager.CreateAsync(user);
                    if (!result.Succeeded) return BadRequest(CreateIdentityProblemResponse(result));

                    result = await userManager.AddToRoleAsync(user, UserRole.User);
                    if (!result.Succeeded) return BadRequest(CreateIdentityProblemResponse(result));

                    result = await userManager.AddLoginAsync(user,
                        new UserLoginInfo(Identity.Constants.LoginProvider.Google, payload.Subject,
                            Identity.Constants.LoginProvider.Google));
                    if (!result.Succeeded) return BadRequest(CreateIdentityProblemResponse(result));

                    await transaction.CommitAsync();
                }
                else
                {
                    var result = await userManager.AddLoginAsync(user,
                        new UserLoginInfo(Identity.Constants.LoginProvider.Google, payload.Subject,
                            Identity.Constants.LoginProvider.Google));
                    if (!result.Succeeded) return BadRequest(CreateIdentityProblemResponse(result));

                    if (!user.EmailConfirmed)
                    {
                        user.EmailConfirmed = true;
                        result = await userManager.UpdateAsync(user);
                        if (!result.Succeeded) return BadRequest(CreateIdentityProblemResponse(result));
                    }
                }
            }

            await signInManager.SignInAsync(user, isPersistent: true);
            return Ok();
        }
        catch (InvalidJwtException)
        {
            return BadRequest(CreateIdentityProblemResponse("InvalidIdToken",
                "The provided Google ID token is invalid."));
        }
        catch
        {
            return Problem("An error occurred during Google login.",
                statusCode: StatusCodes.Status500InternalServerError);
        }
    }

    [HttpPost("refresh")]
    [ProducesResponseType(typeof(AccessTokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshRequest refreshRequest)
    {
        var refreshTokenProtector =
            bearerTokenOptions.Get(IdentityConstants.BearerScheme).RefreshTokenProtector;
        var refreshTicket = refreshTokenProtector.Unprotect(refreshRequest.RefreshToken);

        // Reject the /refresh attempt with a 401 if the token expired or the security stamp validation fails
        if (refreshTicket?.Properties.ExpiresUtc is not { } expiresUtc ||
            timeProvider.GetUtcNow() >= expiresUtc ||
            await signInManager.ValidateSecurityStampAsync(refreshTicket.Principal) is not { } user)
            return Challenge();

        var newPrincipal = await signInManager.CreateUserPrincipalAsync(user);
        return SignIn(newPrincipal, authenticationScheme: IdentityConstants.BearerScheme);
    }

    [HttpGet("confirm-email", Name = ConfirmEmailRouteName)]
    [ProducesResponseType(StatusCodes.Status302Found)]
    public async Task<IActionResult> ConfirmEmail([FromQuery] string userId, [FromQuery] string code,
        [FromQuery] string? changedEmail)
    {
        var clientUrl = configuration["ClientUrl"];
        if (await userManager.FindByIdAsync(userId) is not { } user)
        {
            // We could respond with a 404 instead of a 401 like Identity UI, but that feels like unnecessary information.
            return Redirect($"{clientUrl}/email-confirmation?success=false");
        }

        try
        {
            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
        }
        catch (FormatException)
        {
            return Redirect($"{clientUrl}/email-confirmation?success=false");
        }

        IdentityResult result;

        if (string.IsNullOrEmpty(changedEmail)) result = await userManager.ConfirmEmailAsync(user, code);
        else
        {
            // As with Identity UI, email and username are one and the same. So when we update the email,
            // we need to update the username.
            result = await userManager.ChangeEmailAsync(user, changedEmail, code);

            if (result.Succeeded) result = await userManager.SetUserNameAsync(user, changedEmail);
        }

        return Redirect(!result.Succeeded
            ? $"{clientUrl}/email-confirmation?success=false"
            : $"{clientUrl}/email-confirmation?success=true");
    }

    [HttpPost("send-confirmation-email")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> SendConfirmationEmail([FromBody] ResendConfirmationEmailRequest request)
    {
        var user = await userManager.FindByNameAsync(request.Email);
        if (user != null && !await userManager.IsEmailConfirmedAsync(user))
            await SendConfirmationEmailAsync(user, request.Email);

        return Ok();
    }

    [HttpPost("forgot-password")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest resetRequest)
    {
        var user = await userManager.FindByEmailAsync(resetRequest.Email);

        if (user != null && await userManager.IsEmailConfirmedAsync(user))
        {
            var code = await userManager.GeneratePasswordResetTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            await emailSender.SendPasswordResetCodeAsync(user, resetRequest.Email, HtmlEncoder.Default.Encode(code));
        }

        // Don't reveal that the user does not exist or is not confirmed, so don't return a 200 if we had
        // returned a 400 for an invalid code given a valid user email.
        return Ok();
    }

    [HttpPost("reset-password")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(IdentityProblemResponse), StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest resetRequest)
    {
        var user = await userManager.FindByEmailAsync(resetRequest.Email);

        if (user == null || !await userManager.IsEmailConfirmedAsync(user))
        {
            // Don't reveal that the user does not exist or is not confirmed, so don't return a 200 if we had
            // returned a 400 for an invalid code given a valid user email.
            return BadRequest(
                CreateIdentityProblemResponse(IdentityResult.Failed(userManager.ErrorDescriber.InvalidToken())));
        }

        IdentityResult result;
        try
        {
            var code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(resetRequest.ResetCode));
            result = await userManager.ResetPasswordAsync(user, code, resetRequest.NewPassword);
        }
        catch (FormatException)
        {
            result = IdentityResult.Failed(userManager.ErrorDescriber.InvalidToken());
        }

        if (!result.Succeeded) return BadRequest(CreateIdentityProblemResponse(result));

        return Ok();
    }

    [HttpPost("cookie-logout")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> CookieLogout()
    {
        await signInManager.SignOutAsync();
        return Ok();
    }

    [HttpPost("manage/2fa")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(IdentityProblemResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> TwoFA([FromBody] TwoFactorRequest tfaRequest)
    {
        if (await userManager.GetUserAsync(User) is not { } user) return NotFound();

        if (tfaRequest.Enable == true)
        {
            if (tfaRequest.ResetSharedKey)
                return BadRequest(CreateIdentityProblemResponse("CannotResetSharedKeyAndEnable",
                    "Resetting the 2fa shared key must disable 2fa until a 2fa token based on the new shared key is validated."));

            if (string.IsNullOrEmpty(tfaRequest.TwoFactorCode))
                return BadRequest(CreateIdentityProblemResponse("RequiresTwoFactor",
                    "No 2fa token was provided by the request. A valid 2fa token is required to enable 2fa."));

            if (!await userManager.VerifyTwoFactorTokenAsync(user,
                    userManager.Options.Tokens.AuthenticatorTokenProvider, tfaRequest.TwoFactorCode))
                return BadRequest(CreateIdentityProblemResponse("InvalidTwoFactorCode",
                    "The 2fa token provided by the request was invalid. A valid 2fa token is required to enable 2fa."));

            await userManager.SetTwoFactorEnabledAsync(user, true);
        }
        else if (tfaRequest.Enable == false || tfaRequest.ResetSharedKey)
            await userManager.SetTwoFactorEnabledAsync(user, false);

        if (tfaRequest.ResetSharedKey) await userManager.ResetAuthenticatorKeyAsync(user);

        string[]? recoveryCodes = null;
        if (tfaRequest.ResetRecoveryCodes ||
            (tfaRequest.Enable == true && await userManager.CountRecoveryCodesAsync(user) == 0))
        {
            var recoveryCodesEnumerable = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            recoveryCodes = recoveryCodesEnumerable?.ToArray();
        }

        if (tfaRequest.ForgetMachine) await signInManager.ForgetTwoFactorClientAsync();

        var key = await userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            await userManager.ResetAuthenticatorKeyAsync(user);
            key = await userManager.GetAuthenticatorKeyAsync(user);

            if (string.IsNullOrEmpty(key))
                throw new NotSupportedException("The user manager must produce an authenticator key after reset.");
        }

        return Ok(new TwoFactorResponse
        {
            SharedKey = key,
            RecoveryCodes = recoveryCodes,
            RecoveryCodesLeft = recoveryCodes?.Length ?? await userManager.CountRecoveryCodesAsync(user),
            IsTwoFactorEnabled = await userManager.GetTwoFactorEnabledAsync(user),
            IsMachineRemembered = await signInManager.IsTwoFactorClientRememberedAsync(user),
        });
    }

    [HttpGet("manage/info")]
    [Authorize]
    [ProducesResponseType(typeof(UserInfoDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Info()
    {
        if (await userManager.GetUserAsync(User) is not { } user) return NotFound();

        return Ok(await CreateUserInfoDtoAsync(user, userManager));
    }

    [HttpPost("manage/info")]
    [Authorize]
    [ProducesResponseType(typeof(UserInfoDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(IdentityProblemResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Info([FromBody] InfoRequest infoRequest)
    {
        if (await userManager.GetUserAsync(User) is not { } user) return NotFound();

        if (!string.IsNullOrEmpty(infoRequest.NewEmail) && !_emailAddressAttribute.IsValid(infoRequest.NewEmail))
            return BadRequest(CreateIdentityProblemResponse(
                IdentityResult.Failed(userManager.ErrorDescriber.InvalidEmail(infoRequest.NewEmail))));

        if (!string.IsNullOrEmpty(infoRequest.NewPassword))
        {
            if (string.IsNullOrEmpty(infoRequest.OldPassword))
                return BadRequest(CreateIdentityProblemResponse("OldPasswordRequired",
                    "The old password is required to set a new password. If the old password is forgotten, use /resetPassword."));

            var changePasswordResult =
                await userManager.ChangePasswordAsync(user, infoRequest.OldPassword, infoRequest.NewPassword);
            if (!changePasswordResult.Succeeded) return BadRequest(CreateIdentityProblemResponse(changePasswordResult));
        }

        if (!string.IsNullOrEmpty(infoRequest.NewEmail))
        {
            var email = await userManager.GetEmailAsync(user);

            if (email != infoRequest.NewEmail)
                await SendConfirmationEmailAsync(user, infoRequest.NewEmail, isChange: true);
        }

        return Ok(await CreateUserInfoDtoAsync(user, userManager));
    }

    [HttpGet("manage/roles")]
    [Authorize]
    [ProducesResponseType(typeof(RolesDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Roles()
    {
        var userDb = await userManager.GetUserAsync(User);
        if (userDb == null) return Unauthorized();

        return Ok(new RolesDto
        {
            Roles = (await userManager.GetRolesAsync(userDb)).ToArray()
        });
    }

    private async Task SendConfirmationEmailAsync(CustomUser user, string email, bool isChange = false)
    {
        var code = isChange
            ? await userManager.GenerateChangeEmailTokenAsync(user, email)
            : await userManager.GenerateEmailConfirmationTokenAsync(user);
        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

        var userId = await userManager.GetUserIdAsync(user);
        var routeValues = new RouteValueDictionary
        {
            ["userId"] = userId,
            ["code"] = code,
        };

        if (isChange)
        {
            // This is validated by the /confirmEmail endpoint on change.
            routeValues.Add("changedEmail", email);
        }

        var confirmEmailUrl = Url.Link(ConfirmEmailRouteName, routeValues) ??
                              throw new NotSupportedException(
                                  $"Could not find endpoint named '{ConfirmEmailRouteName}'.");
        await emailSender.SendConfirmationLinkAsync(user, email, HtmlEncoder.Default.Encode(confirmEmailUrl));
    }

    private static IdentityProblemResponse CreateIdentityProblemResponse(string errorCode, string errorDescription)
        => new() { Errors = new Dictionary<string, string[]> { [errorCode] = [errorDescription] } };

    private static IdentityProblemResponse CreateIdentityProblemResponse(IdentityResult result)
        => new()
        {
            Errors = result.Errors.GroupBy(e => e.Code)
                .ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray())
        };

    private static async Task<UserInfoDto> CreateUserInfoDtoAsync(CustomUser user, UserManager<CustomUser> userManager)
        => new()
        {
            Email = await userManager.GetEmailAsync(user) ??
                    throw new NotSupportedException("Users must have an email."),
            IsEmailConfirmed = await userManager.IsEmailConfirmedAsync(user),
        };
}