using FluentEmail.Core;
using FluentEmail.MailKitSmtp;
using Microsoft.AspNetCore.Identity;
using PracticeAspNetCoreIdentity.Server.Models;

namespace PracticeAspNetCoreIdentity.Server;

public class EmailSender(IConfiguration configuration) : IEmailSender<CustomUser>
{
    public Task SendConfirmationLinkAsync(CustomUser user, string email, string confirmationLink)
        => SendEmailAsync(email, "Confirm your email",
            $"<html lang=\"en\"><head></head><body>Please confirm your account by <a href='{confirmationLink}'>clicking here</a>.</body></html>");

    public Task SendPasswordResetLinkAsync(CustomUser user, string email, string resetLink)
        => SendEmailAsync(email, "Reset your password",
            $"<html lang=\"en\"><head></head><body>Please reset your password by <a href='{resetLink}'>clicking here</a>.</body></html>");

    public Task SendPasswordResetCodeAsync(CustomUser user, string email, string resetCode)
        => SendEmailAsync(email, "Reset your password",
            $"<html lang=\"en\"><head></head><body>Please reset your password using the following code:<br>{resetCode}</body></html>");

    private async Task SendEmailAsync(string toEmail, string subject, string message)
    {
        var email = new Email(configuration["EmailAddress"], configuration["EmailDisplayName"])
        {
            Sender = new MailKitSender(new SmtpClientOptions
            {
                Server = configuration["SmtpServer"],
                Port = int.Parse(configuration["SmtpPort"]!),
                User = configuration["SmtpUser"],
                Password = configuration["SmtpPassword"],
                RequiresAuthentication = true
            })
        };

        var response = await email
            .To(toEmail)
            .Subject(subject)
            .Body(message)
            .SendAsync();

        if (!response.Successful)
        {
            throw new Exception("Failed to send email: " + string.Join(", ", response.ErrorMessages));
        }
    }
}