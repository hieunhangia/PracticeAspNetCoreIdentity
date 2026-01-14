using System.Text;
using System.Text.Encodings.Web;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
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
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequest registration)
    {
        var user = new CustomUser
        {
            UserName = registration.Email,
            Email = registration.Email
        };

        await using var transaction = await dbContext.Database.BeginTransactionAsync();

        var result = await userManager.CreateAsync(user, registration.Password);
        if (!result.Succeeded)
        {
            if (result.Errors.All(e => e.Code != "DuplicateEmail"))
            {
                return CreateValidationProblem(result);
            }

            var errors = result.Errors.ToList();
            errors.RemoveAll(e => e.Code == "DuplicateUserName");
            result = IdentityResult.Failed(errors.ToArray());
            return CreateValidationProblem(result);
        }

        result = await userManager.AddToRoleAsync(user, UserRole.User);
        if (!result.Succeeded)
        {
            return CreateValidationProblem(result);
        }

        await transaction.CommitAsync();
        return Created(string.Empty, new { user.Id, user.Email });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest login, [FromQuery] bool? useCookies)
    {
        signInManager.AuthenticationScheme =
            useCookies == true ? IdentityConstants.ApplicationScheme : IdentityConstants.BearerScheme;

        var result = await signInManager.PasswordSignInAsync(login.Email, login.Password, useCookies == true,
            lockoutOnFailure: true);

        if (result.IsLockedOut)
        {
            return Problem("Too many failed login attempts have occurred. Please try again later.",
                title: "Too Many Failed Login Attempts",
                statusCode: StatusCodes.Status400BadRequest);
        }

        if (!result.Succeeded)
        {
            return Problem("Invalid email or password.",
                title: "Login Failed",
                statusCode: StatusCodes.Status400BadRequest);
        }

        return Empty;
    }

    [HttpPost("google-login")]
    public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginRequest request, [FromQuery] bool? useCookies)
    {
        try
        {
            var payload = await GoogleJsonWebSignature.ValidateAsync(request.IdToken,
                new GoogleJsonWebSignature.ValidationSettings { Audience = [configuration["GoogleClientId"]] });

            if (!payload.EmailVerified)
            {
                return Problem("Google account email is not verified.",
                    title: "Google Login Failed",
                    statusCode: StatusCodes.Status400BadRequest);
            }

            var user = await userManager.FindByLoginAsync(Identity.Constants.LoginProvider.Google, payload.Subject);
            if (user == null)
            {
                await using var transaction = await dbContext.Database.BeginTransactionAsync();

                user = await userManager.FindByEmailAsync(payload.Email);
                if (user == null)
                {
                    user = new CustomUser
                    {
                        UserName = payload.Email,
                        Email = payload.Email,
                        EmailConfirmed = true
                    };

                    var result = await userManager.CreateAsync(user);
                    if (!result.Succeeded)
                    {
                        return CreateValidationProblem(result);
                    }

                    result = await userManager.AddToRoleAsync(user, UserRole.User);
                    if (!result.Succeeded)
                    {
                        return CreateValidationProblem(result);
                    }

                    result = await userManager.AddLoginAsync(user,
                        new UserLoginInfo(Identity.Constants.LoginProvider.Google, payload.Subject,
                            Identity.Constants.LoginProvider.Google));
                    if (!result.Succeeded)
                    {
                        return CreateValidationProblem(result);
                    }
                }
                else
                {
                    var result = await userManager.AddLoginAsync(user,
                        new UserLoginInfo(Identity.Constants.LoginProvider.Google, payload.Subject,
                            Identity.Constants.LoginProvider.Google));
                    if (!result.Succeeded)
                    {
                        return CreateValidationProblem(result);
                    }

                    if (!user.EmailConfirmed)
                    {
                        user.EmailConfirmed = true;
                        result = await userManager.UpdateAsync(user);
                        if (!result.Succeeded)
                        {
                            return CreateValidationProblem(result);
                        }
                    }
                }

                await transaction.CommitAsync();
            }

            signInManager.AuthenticationScheme = useCookies == true
                ? IdentityConstants.ApplicationScheme
                : IdentityConstants.BearerScheme;
            await signInManager.SignInAsync(user, useCookies == true);
            return Empty;
        }
        catch (InvalidJwtException)
        {
            return Problem("Invalid Google ID token.",
                title: "Google Login Failed",
                statusCode: StatusCodes.Status400BadRequest);
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

    [HttpPost("send-confirmation-email")]
    [Authorize]
    public async Task<IActionResult> SendConfirmationEmail()
    {
        if (await userManager.GetUserAsync(User) is not { } user)
        {
            return Unauthorized();
        }

        if (user.EmailConfirmed)
        {
            return Problem("Email is already confirmed.",
                title: "Email Already Confirmed",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var clientUrl = configuration["ClientUrl"] ??
                        throw new InvalidOperationException("ClientUrl is not configured.");
        var confirmEmailPath = configuration["ConfirmEmailPath"] ??
                               throw new InvalidOperationException("ConfirmEmailPath is not configured.");

        var code = WebEncoders.Base64UrlEncode(
            Encoding.UTF8.GetBytes(await userManager.GenerateEmailConfirmationTokenAsync(user)));

        var confirmEmailUrl =
            $"{clientUrl.TrimEnd('/')}/{confirmEmailPath.TrimStart('/')}?email={user.Email}&code={code}";

        await emailSender.SendConfirmationLinkAsync(user, user.Email!, HtmlEncoder.Default.Encode(confirmEmailUrl));

        return Ok();
    }

    [HttpPost("confirm-email")]
    public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailRequest confirmEmailRequest)
    {
        if (await userManager.FindByEmailAsync(confirmEmailRequest.Email) is not { } user)
        {
            return Problem("Email confirmation failed. Please try again.",
                title: "Email Confirmation Failed",
                statusCode: StatusCodes.Status400BadRequest);
        }

        if (user.EmailConfirmed)
        {
            return Ok();
        }

        try
        {
            var code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(confirmEmailRequest.Code));
            var result = await userManager.ConfirmEmailAsync(user, code);
            if (!result.Succeeded)
            {
                return Problem("Email confirmation failed. Please try again.",
                    title: "Email Confirmation Failed",
                    statusCode: StatusCodes.Status400BadRequest);
            }

            return Ok();
        }
        catch (FormatException)
        {
            return Problem("Email confirmation failed. Please try again.",
                title: "Email Confirmation Failed",
                statusCode: StatusCodes.Status400BadRequest);
        }
    }

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest resetRequest)
    {
        var user = await userManager.FindByEmailAsync(resetRequest.Email);

        if (user is not { EmailConfirmed: true })
        {
            return Ok();
        }

        var clientUrl = configuration["ClientUrl"] ??
                        throw new InvalidOperationException("ClientUrl is not configured.");
        var resetPasswordPath = configuration["ResetPasswordPath"] ??
                                throw new InvalidOperationException("ResetPasswordPath is not configured.");

        var code = WebEncoders.Base64UrlEncode(
            Encoding.UTF8.GetBytes(await userManager.GeneratePasswordResetTokenAsync(user)));

        var resetPasswordUrl =
            $"{clientUrl.TrimEnd('/')}/{resetPasswordPath.TrimStart('/')}?email={user.Email}&code={code}";

        await emailSender.SendPasswordResetLinkAsync(user, user.Email!, HtmlEncoder.Default.Encode(resetPasswordUrl));

        return Ok();
    }

    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest resetRequest)
    {
        var user = await userManager.FindByEmailAsync(resetRequest.Email);

        if (user is not { EmailConfirmed: true })
        {
            return Problem("Reset password failed. Please try again.",
                title: "Reset Password Failed",
                statusCode: StatusCodes.Status400BadRequest);
        }

        try
        {
            var code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(resetRequest.ResetCode));
            var result = await userManager.ResetPasswordAsync(user, code, resetRequest.NewPassword);
            return result.Succeeded ? Ok() : CreateValidationProblem(result);
        }
        catch (FormatException)
        {
            return Problem("Reset password failed. Please try again.",
                title: "Reset Password Failed",
                statusCode: StatusCodes.Status400BadRequest);
        }
    }

    [HttpPost("cookie-logout")]
    [Authorize]
    public async Task<IActionResult> CookieLogout()
    {
        await signInManager.SignOutAsync();
        return Ok();
    }

    [HttpGet("info")]
    [Authorize]
    public async Task<IActionResult> Info()
    {
        if (await userManager.GetUserAsync(User) is not { } user)
        {
            return Unauthorized();
        }

        return Ok(new UserInfoResponse
        {
            Email = user.Email ?? string.Empty,
            EmailConfirmed = user.EmailConfirmed,
            HasPassword = !string.IsNullOrEmpty(user.PasswordHash),
            Roles = (await userManager.GetRolesAsync(user)).ToList()
        });
    }

    [HttpPost("set-password")]
    [Authorize]
    public async Task<IActionResult> SetPassword([FromBody] SetPasswordRequest setPasswordRequest)
    {
        if (await userManager.GetUserAsync(User) is not { } user)
        {
            return Unauthorized();
        }

        if (!string.IsNullOrEmpty(user.PasswordHash))
        {
            return Problem("Password is already set for this account.",
                title: "Password Already Set",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var result = await userManager.AddPasswordAsync(user, setPasswordRequest.NewPassword);
        return result.Succeeded ? Ok() : CreateValidationProblem(result);
    }

    [HttpPost("change-password")]
    [Authorize]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest changePasswordRequest)
    {
        if (await userManager.GetUserAsync(User) is not { } user)
        {
            return Unauthorized();
        }

        if (string.IsNullOrEmpty(user.PasswordHash))
        {
            return Problem("No password is set for this account.",
                title: "Change Password Failed",
                statusCode: StatusCodes.Status400BadRequest);
        }

        var result = await userManager.ChangePasswordAsync(user, changePasswordRequest.OldPassword,
            changePasswordRequest.NewPassword);
        return result.Succeeded ? Ok() : CreateValidationProblem(result);
    }

    private ActionResult CreateValidationProblem(IdentityResult result)
    {
        var modelState = new ModelStateDictionary();
        foreach (var error in result.Errors)
        {
            modelState.AddModelError(error.Code, error.Description);
        }

        return ValidationProblem(modelState);
    }
}