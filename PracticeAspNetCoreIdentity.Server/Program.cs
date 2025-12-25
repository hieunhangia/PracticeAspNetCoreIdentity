using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PracticeAspNetCoreIdentity.Server;
using PracticeAspNetCoreIdentity.Server.Models;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddAuthorization();

builder.Services.AddIdentityApiEndpoints<CustomUser>()
    .AddRoles<IdentityRole<Guid>>()
    .AddEntityFrameworkStores<AppDbContext>();

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

using (var scope = app.Services.CreateScope())
{
    await SeedData.InitializeAsync(scope.ServiceProvider, builder.Configuration);
}

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
app.MapIdentityApiCustom();


app.Run();