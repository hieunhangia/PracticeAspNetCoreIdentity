using FluentEmail.Core;
using Microsoft.AspNetCore.Identity;
using PracticeAspNetCoreIdentity.Server.Identity.Constants;
using PracticeAspNetCoreIdentity.Server.Models;

namespace PracticeAspNetCoreIdentity.Server;

public class EmailSender(IFluentEmail fluentEmail) : IEmailSender<CustomUser>
{
    public Task SendConfirmationLinkAsync(CustomUser user, string email, string confirmationLink)
        => SendEmailAsync(email, "Confirm your email",
            $"""
             <html lang="en">
             <head>
             </head>
             <body>
                Please confirm your account by <a href='{confirmationLink}'>clicking here</a>.<br>
                This link is valid for {TokenExpiredTime.EmailConfirmationHours} hours. During this time, your email is reserved, so you won't need to register again.
                If you didn't request this, you can safely ignore this email.
             </body>
             </html>
             """);

    public Task SendPasswordResetLinkAsync(CustomUser user, string email, string resetLink)
        => Task.CompletedTask; // Redundant method when using MapIdentityApi

    public Task SendPasswordResetCodeAsync(CustomUser user, string email, string resetCode)
        => SendEmailAsync(email, "Reset your password",
            $"""
             <html lang="en">
             <head>
             </head>
             <body>
                Please reset your password using the following code:<br>{resetCode}<br>
                Code will expire in {TokenExpiredTime.PasswordResetCodeMinutes} minute(s).
             </body>
             </html>
             """);

    private async Task SendEmailAsync(string toEmail, string subject, string message)
    {
        var response = await fluentEmail
            .To(toEmail)
            .Subject(subject)
            .Body(message)
            .SendAsync();

        if (!response.Successful)
            throw new Exception("Failed to send email: " + string.Join(", ", response.ErrorMessages));
    }
}