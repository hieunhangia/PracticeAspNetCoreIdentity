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
    IEmailSender<CustomUser> emailSender,
    IOptionsMonitor<BearerTokenOptions> bearerTokenOptions,
    TimeProvider timeProvider
) : ControllerBase
{
    private static readonly EmailAddressAttribute _emailAddressAttribute = new();

    private const string ConfirmEmailRouteName = "ConfirmEmailRoute";

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest registration)
    {
        if (string.IsNullOrEmpty(registration.Email) || !_emailAddressAttribute.IsValid(registration.Email))
        {
            return BadRequest(CreateValidationProblem(IdentityResult.Failed(userManager.ErrorDescriber.InvalidEmail(registration.Email))));
        }

        var user = new CustomUser
        {
            UserName = registration.Email,
            Email = registration.Email
        };

        await using var transaction = await dbContext.Database.BeginTransactionAsync();

        var result = await userManager.CreateAsync(user, registration.Password);
        if (!result.Succeeded)
        {
            return BadRequest(CreateValidationProblem(result));
        }

        result = await userManager.AddToRoleAsync(user, UserRole.User);
        if (!result.Succeeded)
        {
            return BadRequest(CreateValidationProblem(result));
        }

        await transaction.CommitAsync();
        return Ok();
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest login, [FromQuery] bool? useCookies,
        [FromQuery] bool? useSessionCookies)
    {
        var isPersistent = useCookies == true && useSessionCookies != true;
        signInManager.AuthenticationScheme = useCookies == true || useSessionCookies == true
            ? IdentityConstants.ApplicationScheme
            : IdentityConstants.BearerScheme;

        var result = await signInManager.PasswordSignInAsync(login.Email, login.Password, isPersistent, lockoutOnFailure: true);

        if (result.IsLockedOut)
        {
            return BadRequest(CreateValidationProblem("TooManyFailedLoginAttempts",
                "Too many failed login attempts have occurred. Please try again later."));
        }

        if (!result.Succeeded)
        {
            return BadRequest(CreateValidationProblem("InvalidLogin",
                "The provided login credentials are invalid. Please check your email and password and try again."));
        }

        return Ok();
    }

    [HttpPost("google-login")]
    public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginRequest request, [FromQuery] bool? useCookies,
        [FromQuery] bool? useSessionCookies)
    {
        try
        {
            var payload = await GoogleJsonWebSignature.ValidateAsync(request.IdToken, new GoogleJsonWebSignature.ValidationSettings { Audience = [configuration["GoogleClientId"]] });

            if (!payload.EmailVerified)
            {
                return BadRequest(CreateValidationProblem("UnverifiedEmail", "The email address is not verified by Google and cannot be used to log in."));
            }

            var user = await userManager.FindByLoginAsync(Identity.Constants.LoginProvider.Google, payload.Subject);
            if (user == null)
            {
                user = await userManager.FindByEmailAsync(payload.Email);
                if (user == null)
                {
                    user = new CustomUser
                    {
                        UserName = payload.Email,
                        Email = payload.Email,
                        EmailConfirmed = true
                    };

                    await using var transaction = await dbContext.Database.BeginTransactionAsync();

                    var result = await userManager.CreateAsync(user);
                    if (!result.Succeeded)
                    {
                        return BadRequest(CreateValidationProblem(result));
                    }

                    result = await userManager.AddToRoleAsync(user, UserRole.User);
                    if (!result.Succeeded)
                    {
                        return BadRequest(CreateValidationProblem(result));
                    }

                    result = await userManager.AddLoginAsync(user,
                        new UserLoginInfo(Identity.Constants.LoginProvider.Google, payload.Subject,
                            Identity.Constants.LoginProvider.Google));
                    if (!result.Succeeded)
                    {
                        return BadRequest(CreateValidationProblem(result));
                    }

                    await transaction.CommitAsync();
                }
                else
                {
                    var result = await userManager.AddLoginAsync(user,
                        new UserLoginInfo(Identity.Constants.LoginProvider.Google, payload.Subject,
                            Identity.Constants.LoginProvider.Google));
                    if (!result.Succeeded)
                    {
                        return BadRequest(CreateValidationProblem(result));
                    }

                    if (!user.EmailConfirmed)
                    {
                        user.EmailConfirmed = true;
                        result = await userManager.UpdateAsync(user);
                        if (!result.Succeeded)
                        {
                            return BadRequest(CreateValidationProblem(result));
                        }
                    }
                }
            }

            signInManager.AuthenticationScheme = useCookies == true || useSessionCookies == true
                ? IdentityConstants.ApplicationScheme
                : IdentityConstants.BearerScheme;
            await signInManager.SignInAsync(user, useCookies == true && useSessionCookies != true);
            return Ok();
        }
        catch (InvalidJwtException)
        {
            return BadRequest(CreateValidationProblem("InvalidIdToken", "The provided Google ID token is invalid."));
        }
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshRequest refreshRequest)
    {
        var refreshTokenProtector = bearerTokenOptions.Get(IdentityConstants.BearerScheme).RefreshTokenProtector;
        var refreshTicket = refreshTokenProtector.Unprotect(refreshRequest.RefreshToken);

        if (refreshTicket?.Properties.ExpiresUtc is not { } expiresUtc ||
            timeProvider.GetUtcNow() >= expiresUtc ||
            await signInManager.ValidateSecurityStampAsync(refreshTicket.Principal) is not { } user)
        {
            return Challenge();
        }

        var newPrincipal = await signInManager.CreateUserPrincipalAsync(user);
        return SignIn(newPrincipal, authenticationScheme: IdentityConstants.BearerScheme);
    }

    [HttpGet("confirm-email", Name = ConfirmEmailRouteName)]
    public async Task<IActionResult> ConfirmEmail([FromQuery] string userId, [FromQuery] string code,
        [FromQuery] string? changedEmail)
    {
        var clientUrl = configuration["ClientUrl"];
        if (await userManager.FindByIdAsync(userId) is not { } user)
        {
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

        if (string.IsNullOrEmpty(changedEmail))
        {
            result = await userManager.ConfirmEmailAsync(user, code);
        }
        else
        {
            result = await userManager.ChangeEmailAsync(user, changedEmail, code);

            if (result.Succeeded)
            {
                result = await userManager.SetUserNameAsync(user, changedEmail);
            }
        }

        return Redirect(!result.Succeeded
            ? $"{clientUrl}/email-confirmation?success=false"
            : $"{clientUrl}/email-confirmation?success=true");
    }

    [HttpPost("send-confirmation-email")]
    public async Task<IActionResult> SendConfirmationEmail([FromBody] ResendConfirmationEmailRequest request)
    {
        var user = await userManager.FindByNameAsync(request.Email);
        if (user != null && !await userManager.IsEmailConfirmedAsync(user))
        {
            await SendConfirmationEmailAsync(user, request.Email);
        }

        return Ok();
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest resetRequest)
    {
        var user = await userManager.FindByEmailAsync(resetRequest.Email);

        if (user == null || !await userManager.IsEmailConfirmedAsync(user))
        {
            return Ok();
        }
        
        var code = await userManager.GeneratePasswordResetTokenAsync(user);
        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
        await emailSender.SendPasswordResetCodeAsync(user, resetRequest.Email, HtmlEncoder.Default.Encode(code));

        return Ok();
    }

    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest resetRequest)
    {
        var user = await userManager.FindByEmailAsync(resetRequest.Email);

        if (user == null || !await userManager.IsEmailConfirmedAsync(user))
        {
            return BadRequest(CreateValidationProblem(IdentityResult.Failed(userManager.ErrorDescriber.InvalidToken())));
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

        if (!result.Succeeded)
        {
            return BadRequest(CreateValidationProblem(result));
        }

        return Ok();
    }

    [HttpPost("cookie-logout")]
    [Authorize]
    public async Task<IActionResult> CookieLogout()
    {
        await signInManager.SignOutAsync();
        return Ok();
    }

    [HttpGet("manage/info")]
    [Authorize]
    public async Task<IActionResult> Info()
    {
        if (await userManager.GetUserAsync(User) is not { } user)
        {
            return NotFound();
        }

        return Ok(await CreateUserInfoResponseAsync(user));
    }

    [HttpPost("manage/info")]
    [Authorize]
    public async Task<IActionResult> Info([FromBody] InfoRequest infoRequest)
    {
        if (await userManager.GetUserAsync(User) is not { } user)
        {
            return NotFound();
        }

        if (!string.IsNullOrEmpty(infoRequest.NewEmail) && !_emailAddressAttribute.IsValid(infoRequest.NewEmail))
        {
            return BadRequest(CreateValidationProblem(IdentityResult.Failed(userManager.ErrorDescriber.InvalidEmail(infoRequest.NewEmail))));
        }

        if (!string.IsNullOrEmpty(infoRequest.NewPassword))
        {
            if (await userManager.HasPasswordAsync(user))
            {
                if (string.IsNullOrEmpty(infoRequest.OldPassword))
                {
                    return BadRequest(CreateValidationProblem("OldPasswordRequired", "The old password is required to set a new password. If the old password is forgotten, use /resetPassword."));
                }

                var changePasswordResult = await userManager.ChangePasswordAsync(user, infoRequest.OldPassword, infoRequest.NewPassword);
                if (!changePasswordResult.Succeeded)
                {
                    return BadRequest(CreateValidationProblem(changePasswordResult));
                }
            }
            else
            {
                var addPasswordResult = await userManager.AddPasswordAsync(user, infoRequest.NewPassword);
                if (!addPasswordResult.Succeeded)
                {
                    return BadRequest(CreateValidationProblem(addPasswordResult));
                }
            }
        }

        if (!string.IsNullOrEmpty(infoRequest.NewEmail))
        {
            var email = await userManager.GetEmailAsync(user);

            if (email != infoRequest.NewEmail)
                await SendConfirmationEmailAsync(user, infoRequest.NewEmail, isChange: true);
        }

        return Ok(await CreateUserInfoResponseAsync(user));
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

    private static ValidationProblemDetails CreateValidationProblem(string errorCode, string errorDescription)
        => new() { Errors = new Dictionary<string, string[]> { [errorCode] = [errorDescription] } };

    private static ValidationProblemDetails CreateValidationProblem(IdentityResult result)
        => new()
        {
            Errors = result.Errors.GroupBy(e => e.Code)
                .ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray())
        };

    private async Task<UserInfoResponse> CreateUserInfoResponseAsync(CustomUser user)
    {
        var emailTask = userManager.GetEmailAsync(user);
        var emailConfirmedTask = userManager.IsEmailConfirmedAsync(user);
        var hasPasswordTask = userManager.HasPasswordAsync(user);
        var rolesTask = userManager.GetRolesAsync(user);
        await Task.WhenAll(emailTask, emailConfirmedTask, hasPasswordTask, rolesTask);
        return new UserInfoResponse
        {
            Email = await emailTask ?? throw new NotSupportedException("Users must have an email."),
            EmailConfirmed = await emailConfirmedTask,
            HasPassword = await hasPasswordTask,
            Roles = (await rolesTask).ToList()
        };
    }
}