using FluentEmail.MailKitSmtp;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PracticeAspNetCoreIdentity.Server;
using PracticeAspNetCoreIdentity.Server.Identity.TokenProviders;
using PracticeAspNetCoreIdentity.Server.Models;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

builder.Services.AddOpenApi();

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddAuthorization();

builder.Services.AddIdentityApiEndpoints<AppUser>()
    .AddRoles<IdentityRole<Guid>>()
    .AddEntityFrameworkStores<AppDbContext>();

builder.Services.AddFluentEmail(builder.Configuration["EmailAddress"], builder.Configuration["EmailDisplayName"])
    .AddMailKitSender(new SmtpClientOptions
    {
        Server = builder.Configuration["SmtpServer"],
        Port = int.Parse(builder.Configuration["SmtpPort"]!),
        User = builder.Configuration["SmtpUser"],
        Password = builder.Configuration["SmtpPassword"],
        RequiresAuthentication = true
    });

builder.Services.AddTransient<IEmailSender<AppUser>, EmailSender>();

builder.Services.Configure<IdentityOptions>(options =>
{
    //options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5); // default is 5 minutes
    //options.Lockout.MaxFailedAccessAttempts = 5; // default is 5
    //options.Lockout.AllowedForNewUsers = true; // default is true

    //options.Password.RequireDigit = true; // default is true
    //options.Password.RequireLowercase = true; // default is true
    //options.Password.RequireNonAlphanumeric = true; // default is true
    //options.Password.RequireUppercase = true; // default is true
    //options.Password.RequiredLength = 6; // default is 6
    //options.Password.RequiredUniqueChars = 1; // default is 1

    //options.SignIn.RequireConfirmedEmail = false; //default is false
    //options.SignIn.RequireConfirmedAccount = false; //default is false
    //options.SignIn.RequireConfirmedPhoneNumber = false; //default is false

    //options.Tokens.

    //options.User.AllowedUserNameCharacters =
    //"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    // default is "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+"
    options.User.RequireUniqueEmail = true; // default is false

    options.Tokens.ProviderMap.Add("CustomEmailConfirmation",
        new TokenProviderDescriptor(typeof(CustomEmailConfirmationTokenProvider)));
    options.Tokens.EmailConfirmationTokenProvider = "CustomEmailConfirmation";

    options.Tokens.ProviderMap.Add("CustomPasswordReset",
        new TokenProviderDescriptor(typeof(CustomPasswordResetTokenProvider)));
    options.Tokens.PasswordResetTokenProvider = "CustomPasswordReset";
});

builder.Services.AddTransient<CustomEmailConfirmationTokenProvider>();
builder.Services.AddTransient<CustomPasswordResetTokenProvider>();

builder.Services.ConfigureApplicationCookie(o =>
{
    o.ExpireTimeSpan = TimeSpan.FromDays(365); // default is 14 days
    //o.SlidingExpiration = true; // default is true
});

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowClient",
        policy => policy.WithOrigins(builder.Configuration["ClientUrl"]!)
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials());
});

var app = builder.Build();

await SeedData.InitializeAsync(app.Services);

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseHttpsRedirection();
app.UseCors("AllowClient");
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();


app.Run();