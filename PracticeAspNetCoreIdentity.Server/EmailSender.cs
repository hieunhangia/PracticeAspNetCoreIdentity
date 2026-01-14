using FluentEmail.Core;
using Microsoft.AspNetCore.Identity;
using PracticeAspNetCoreIdentity.Server.Identity.Constants;
using PracticeAspNetCoreIdentity.Server.Models;

namespace PracticeAspNetCoreIdentity.Server;

public class EmailSender(IFluentEmail fluentEmail) : IEmailSender<AppUser>
{
    public Task SendConfirmationLinkAsync(AppUser user, string email, string confirmationLink)
        => SendEmailAsync(email, "Confirm your email",
            $"""
             <html lang="en">
             <head>
             </head>
             <body>
                Please confirm your account by <a href='{confirmationLink}'>clicking here</a>.<br>
                This link is valid for {TokenExpiredTime.EmailConfirmationHours} hours.<br>
                If you didn't request this, you can safely ignore this email.
             </body>
             </html>
             """);

    public Task SendPasswordResetLinkAsync(AppUser user, string email, string resetLink) =>
        SendEmailAsync(email, "Reset your password",
            $"""
             <html lang="en">
             <head>
             </head>
             <body>
                Please reset your password using <a href='{resetLink}'>this link</a>.<br>
                Link will expire in {TokenExpiredTime.PasswordResetCodeMinutes} minutes.<br>
                If you didn't request this, you can safely ignore this email.
             </body>
             </html>
             """);

    public Task SendPasswordResetCodeAsync(AppUser user, string email, string resetCode) =>
        Task.CompletedTask; // Not implemented


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