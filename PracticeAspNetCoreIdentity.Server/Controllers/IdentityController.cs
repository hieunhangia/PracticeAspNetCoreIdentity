using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Text;
using System.Text.Encodings.Web;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using PracticeAspNetCoreIdentity.Server.Models;
using PracticeAspNetCoreIdentity.Shared.Constants;
using PracticeAspNetCoreIdentity.Shared.Models;

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
    TimeProvider timeProvider,
    LinkGenerator linkGenerator
) : ControllerBase
{
    // Validate the email address using DataAnnotations like the UserValidator does when RequireUniqueEmail = true.
    private static readonly EmailAddressAttribute _emailAddressAttribute = new();

    private const string ConfirmEmailRouteName = "ConfirmEmailRoute";

    [HttpPost("register")]
    public async Task<Results<Ok, ValidationProblem>> Register([FromBody] RegisterRequest registration)
    {
        if (!userManager.SupportsUserEmail)
        {
            throw new NotSupportedException($"{nameof(IdentityController)} requires a user store with email support.");
        }

        var emailStore = (IUserEmailStore<CustomUser>)userStore;
        var email = registration.Email;

        if (string.IsNullOrEmpty(email) || !_emailAddressAttribute.IsValid(email))
        {
            return CreateValidationProblem(IdentityResult.Failed(userManager.ErrorDescriber.InvalidEmail(email)));
        }

        var user = new CustomUser();
        await userStore.SetUserNameAsync(user, email, CancellationToken.None);
        await emailStore.SetEmailAsync(user, email, CancellationToken.None);

        await using var transaction = await dbContext.Database.BeginTransactionAsync();

        var result = await userManager.CreateAsync(user, registration.Password);
        if (!result.Succeeded) return CreateValidationProblem(result);

        var roleResult = await userManager.AddToRoleAsync(user, UserRole.User);
        if (!roleResult.Succeeded) return CreateValidationProblem(roleResult);

        await transaction.CommitAsync();

        await SendConfirmationEmailAsync(user, email);
        return TypedResults.Ok();
    }

    [HttpPost("login")]
    public async Task<Results<Ok<AccessTokenResponse>, EmptyHttpResult, ProblemHttpResult>> Login(
        [FromBody] LoginRequest login,
        [FromQuery] bool? useCookies,
        [FromQuery] bool? useSessionCookies)
    {
        var useCookieScheme = (useCookies == true) || (useSessionCookies == true);
        var isPersistent = (useCookies == true) && (useSessionCookies != true);
        signInManager.AuthenticationScheme =
            useCookieScheme ? IdentityConstants.ApplicationScheme : IdentityConstants.BearerScheme;

        var result =
            await signInManager.PasswordSignInAsync(login.Email, login.Password, isPersistent,
                lockoutOnFailure: true);

        if (result.RequiresTwoFactor)
        {
            if (!string.IsNullOrEmpty(login.TwoFactorCode))
            {
                result = await signInManager.TwoFactorAuthenticatorSignInAsync(login.TwoFactorCode, isPersistent,
                    rememberClient: isPersistent);
            }
            else if (!string.IsNullOrEmpty(login.TwoFactorRecoveryCode))
            {
                result = await signInManager.TwoFactorRecoveryCodeSignInAsync(login.TwoFactorRecoveryCode);
            }
        }

        if (!result.Succeeded)
        {
            return TypedResults.Problem(result.ToString(), statusCode: StatusCodes.Status401Unauthorized);
        }

        // The signInManager already produced the needed response in the form of a cookie or bearer token.
        return TypedResults.Empty;
    }

    [HttpPost("cookie-google-login")]
    public async Task<IActionResult> CookieGoogleLogin([FromBody] GoogleLoginRequest request)
    {
        try
        {
            var payload = await GoogleJsonWebSignature.ValidateAsync(request.IdToken,
                new GoogleJsonWebSignature.ValidationSettings { Audience = [configuration["GoogleClientId"]] });
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

                    var registerResult = await userManager.CreateAsync(user);
                    if (!registerResult.Succeeded) return BadRequest(registerResult.Errors);

                    var roleResult = await userManager.AddToRoleAsync(user, UserRole.User);
                    if (!roleResult.Succeeded) return BadRequest(roleResult.Errors);

                    var addLoginResult = await userManager.AddLoginAsync(user,
                        new UserLoginInfo(Identity.Constants.LoginProvider.Google, payload.Subject,
                            Identity.Constants.LoginProvider.Google));
                    if (!addLoginResult.Succeeded) return BadRequest(addLoginResult.Errors);

                    await transaction.CommitAsync();
                }
                else
                {
                    var addLoginResult = await userManager.AddLoginAsync(user,
                        new UserLoginInfo(Identity.Constants.LoginProvider.Google, payload.Subject,
                            Identity.Constants.LoginProvider.Google));
                    if (!addLoginResult.Succeeded) return BadRequest(addLoginResult.Errors);
                }
            }

            await signInManager.SignInAsync(user, isPersistent: true);
            return Ok();
        }
        catch (InvalidJwtException)
        {
            return BadRequest("Invalid Google Token");
        }
        catch
        {
            return Problem("An error occurred during Google login.");
        }
    }

    [HttpPost("refresh")]
    public async Task<Results<Ok<AccessTokenResponse>, UnauthorizedHttpResult, SignInHttpResult, ChallengeHttpResult>>
        RefreshToken([FromBody] RefreshRequest refreshRequest)
    {
        var refreshTokenProtector =
            bearerTokenOptions.Get(IdentityConstants.BearerScheme).RefreshTokenProtector;
        var refreshTicket = refreshTokenProtector.Unprotect(refreshRequest.RefreshToken);

        // Reject the /refresh attempt with a 401 if the token expired or the security stamp validation fails
        if (refreshTicket?.Properties.ExpiresUtc is not { } expiresUtc ||
            timeProvider.GetUtcNow() >= expiresUtc ||
            await signInManager.ValidateSecurityStampAsync(refreshTicket.Principal) is not { } user)
        {
            return TypedResults.Challenge();
        }

        var newPrincipal = await signInManager.CreateUserPrincipalAsync(user);
        return TypedResults.SignIn(newPrincipal, authenticationScheme: IdentityConstants.BearerScheme);
    }

    [HttpGet("confirm-email", Name = ConfirmEmailRouteName)]
    public async Task<Results<ContentHttpResult, UnauthorizedHttpResult>> ConfirmEmail
    (
        [FromQuery] string userId,
        [FromQuery] string code,
        [FromQuery] string? changedEmail
    )
    {
        if (await userManager.FindByIdAsync(userId) is not { } user)
        {
            // We could respond with a 404 instead of a 401 like Identity UI, but that feels like unnecessary information.
            return TypedResults.Unauthorized();
        }

        try
        {
            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
        }
        catch (FormatException)
        {
            return TypedResults.Unauthorized();
        }

        IdentityResult result;

        if (string.IsNullOrEmpty(changedEmail))
        {
            result = await userManager.ConfirmEmailAsync(user, code);
        }
        else
        {
            // As with Identity UI, email and username are one and the same. So when we update the email,
            // we need to update the username.
            result = await userManager.ChangeEmailAsync(user, changedEmail, code);

            if (result.Succeeded)
            {
                result = await userManager.SetUserNameAsync(user, changedEmail);
            }
        }

        if (!result.Succeeded)
        {
            return TypedResults.Unauthorized();
        }

        return TypedResults.Text("Thank you for confirming your email.");
    }

    [HttpPost("resend-confirmation-email")]
    public async Task<Ok> ResendConfirmationEmail([FromBody] ResendConfirmationEmailRequest resendRequest)
    {
        var user = await userManager.FindByNameAsync(resendRequest.Email);
        if (user != null && !await userManager.IsEmailConfirmedAsync(user))
        {
            await SendConfirmationEmailAsync(user, resendRequest.Email);
        }

        return TypedResults.Ok();
    }

    [HttpPost("forgot-password")]
    public async Task<Results<Ok, ValidationProblem>> ForgotPassword([FromBody] ForgotPasswordRequest resetRequest)
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
        return TypedResults.Ok();
    }

    [HttpPost("reset-password")]
    public async Task<Results<Ok, ValidationProblem>> ResetPassword([FromBody] ResetPasswordRequest resetRequest)
    {
        var user = await userManager.FindByEmailAsync(resetRequest.Email);

        if (user == null || !await userManager.IsEmailConfirmedAsync(user))
        {
            // Don't reveal that the user does not exist or is not confirmed, so don't return a 200 if we had
            // returned a 400 for an invalid code given a valid user email.
            return CreateValidationProblem(IdentityResult.Failed(userManager.ErrorDescriber.InvalidToken()));
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
            return CreateValidationProblem(result);
        }

        return TypedResults.Ok();
    }

    [HttpPost("cookie-logout")]
    [Authorize]
    public async Task<IActionResult> CookieLogout()
    {
        await signInManager.SignOutAsync();
        return Ok();
    }

    [HttpPost("manage/2fa")]
    [Authorize]
    public async Task<Results<Ok<TwoFactorResponse>, ValidationProblem, NotFound>> TwoFA(
        [FromBody] TwoFactorRequest tfaRequest)
    {
        if (await userManager.GetUserAsync(User) is not { } user)
        {
            return TypedResults.NotFound();
        }

        if (tfaRequest.Enable == true)
        {
            if (tfaRequest.ResetSharedKey)
            {
                return CreateValidationProblem("CannotResetSharedKeyAndEnable",
                    "Resetting the 2fa shared key must disable 2fa until a 2fa token based on the new shared key is validated.");
            }

            if (string.IsNullOrEmpty(tfaRequest.TwoFactorCode))
            {
                return CreateValidationProblem("RequiresTwoFactor",
                    "No 2fa token was provided by the request. A valid 2fa token is required to enable 2fa.");
            }

            if (!await userManager.VerifyTwoFactorTokenAsync(user,
                    userManager.Options.Tokens.AuthenticatorTokenProvider, tfaRequest.TwoFactorCode))
            {
                return CreateValidationProblem("InvalidTwoFactorCode",
                    "The 2fa token provided by the request was invalid. A valid 2fa token is required to enable 2fa.");
            }

            await userManager.SetTwoFactorEnabledAsync(user, true);
        }
        else if (tfaRequest.Enable == false || tfaRequest.ResetSharedKey)
        {
            await userManager.SetTwoFactorEnabledAsync(user, false);
        }

        if (tfaRequest.ResetSharedKey)
        {
            await userManager.ResetAuthenticatorKeyAsync(user);
        }

        string[]? recoveryCodes = null;
        if (tfaRequest.ResetRecoveryCodes ||
            (tfaRequest.Enable == true && await userManager.CountRecoveryCodesAsync(user) == 0))
        {
            var recoveryCodesEnumerable = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            recoveryCodes = recoveryCodesEnumerable?.ToArray();
        }

        if (tfaRequest.ForgetMachine)
        {
            await signInManager.ForgetTwoFactorClientAsync();
        }

        var key = await userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            await userManager.ResetAuthenticatorKeyAsync(user);
            key = await userManager.GetAuthenticatorKeyAsync(user);

            if (string.IsNullOrEmpty(key))
            {
                throw new NotSupportedException("The user manager must produce an authenticator key after reset.");
            }
        }

        return TypedResults.Ok(new TwoFactorResponse
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
    public async Task<Results<Ok<InfoResponse>, ValidationProblem, NotFound>> Info()
    {
        if (await userManager.GetUserAsync(User) is not { } user)
        {
            return TypedResults.NotFound();
        }

        return TypedResults.Ok(await CreateInfoResponseAsync(user, userManager));
    }

    [HttpPost("manage/info")]
    [Authorize]
    public async Task<Results<Ok<InfoResponse>, ValidationProblem, NotFound>> Info([FromBody] InfoRequest infoRequest)
    {
        if (await userManager.GetUserAsync(User) is not { } user)
        {
            return TypedResults.NotFound();
        }

        if (!string.IsNullOrEmpty(infoRequest.NewEmail) && !_emailAddressAttribute.IsValid(infoRequest.NewEmail))
        {
            return CreateValidationProblem(
                IdentityResult.Failed(userManager.ErrorDescriber.InvalidEmail(infoRequest.NewEmail)));
        }

        if (!string.IsNullOrEmpty(infoRequest.NewPassword))
        {
            if (string.IsNullOrEmpty(infoRequest.OldPassword))
            {
                return CreateValidationProblem("OldPasswordRequired",
                    "The old password is required to set a new password. If the old password is forgotten, use /resetPassword.");
            }

            var changePasswordResult =
                await userManager.ChangePasswordAsync(user, infoRequest.OldPassword, infoRequest.NewPassword);
            if (!changePasswordResult.Succeeded)
            {
                return CreateValidationProblem(changePasswordResult);
            }
        }

        if (!string.IsNullOrEmpty(infoRequest.NewEmail))
        {
            var email = await userManager.GetEmailAsync(user);

            if (email != infoRequest.NewEmail)
            {
                await SendConfirmationEmailAsync(user, infoRequest.NewEmail, isChange: true);
            }
        }

        return TypedResults.Ok(await CreateInfoResponseAsync(user, userManager));
    }

    [HttpGet("manage/roles")]
    [Authorize]
    public async Task<IActionResult> Roles()
    {
        var userDb = await userManager.GetUserAsync(User);
        if (userDb == null) return Unauthorized();

        var roles = await userManager.GetRolesAsync(userDb);
        return Ok(roles);
    }

    private async Task SendConfirmationEmailAsync(CustomUser user, string email, bool isChange = false)
    {
        var code = isChange
            ? await userManager.GenerateChangeEmailTokenAsync(user, email)
            : await userManager.GenerateEmailConfirmationTokenAsync(user);
        code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

        var userId = await userManager.GetUserIdAsync(user);
        var routeValues = new RouteValueDictionary()
        {
            ["userId"] = userId,
            ["code"] = code,
        };

        if (isChange)
        {
            // This is validated by the /confirmEmail endpoint on change.
            routeValues.Add("changedEmail", email);
        }

        var confirmEmailUrl = linkGenerator.GetUriByName(HttpContext, ConfirmEmailRouteName, routeValues) ??
                              throw new NotSupportedException(
                                  $"Could not find endpoint named '{ConfirmEmailRouteName}'.");

        await emailSender.SendConfirmationLinkAsync(user, email, HtmlEncoder.Default.Encode(confirmEmailUrl));
    }

    private static ValidationProblem CreateValidationProblem(string errorCode, string errorDescription) =>
        TypedResults.ValidationProblem(new Dictionary<string, string[]>
        {
            { errorCode, [errorDescription] }
        });

    private static ValidationProblem CreateValidationProblem(IdentityResult result)
    {
        // We expect a single error code and description in the normal case.
        // This could be golfed with GroupBy and ToDictionary, but perf! :P
        Debug.Assert(!result.Succeeded);
        var errorDictionary = new Dictionary<string, string[]>(1);

        foreach (var error in result.Errors)
        {
            string[] newDescriptions;

            if (errorDictionary.TryGetValue(error.Code, out var descriptions))
            {
                newDescriptions = new string[descriptions.Length + 1];
                Array.Copy(descriptions, newDescriptions, descriptions.Length);
                newDescriptions[descriptions.Length] = error.Description;
            }
            else
            {
                newDescriptions = [error.Description];
            }

            errorDictionary[error.Code] = newDescriptions;
        }

        return TypedResults.ValidationProblem(errorDictionary);
    }

    private static async Task<InfoResponse> CreateInfoResponseAsync(CustomUser user,
        UserManager<CustomUser> userManager)
    {
        return new InfoResponse
        {
            Email = await userManager.GetEmailAsync(user) ??
                    throw new NotSupportedException("Users must have an email."),
            IsEmailConfirmed = await userManager.IsEmailConfirmedAsync(user),
        };
    }
}