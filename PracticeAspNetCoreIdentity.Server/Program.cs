using FluentEmail.MailKitSmtp;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PracticeAspNetCoreIdentity.Server;
using PracticeAspNetCoreIdentity.Server.Identity;
using PracticeAspNetCoreIdentity.Server.Models;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

builder.Services.AddOpenApi();

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddAuthorization();

builder.Services.AddIdentityApiEndpoints<CustomUser>()
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

builder.Services.AddTransient<IEmailSender<CustomUser>, EmailSender>();

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

    options.SignIn.RequireConfirmedEmail = true; //default is false
    //options.SignIn.RequireConfirmedAccount = false; //default is false
    //options.SignIn.RequireConfirmedPhoneNumber = false; //default is false

    //options.Tokens.

    //options.User.AllowedUserNameCharacters =
    //"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    // default is "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+"
    options.User.RequireUniqueEmail = true; // default is false
});

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowBlazorWasm",
        policy => policy.WithOrigins(builder.Configuration["BlazorWasmOrigin"]!)
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
app.UseCors("AllowBlazorWasm");
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapIdentityApi();


app.Run();