using System.Collections.ObjectModel;

namespace PracticeAspNetCoreIdentity.Shared.Constants;

public static class UserRole
{
    public const string Administrator = "Administrator";
    public const string Manager = "Manager";
    public const string User = "User";

    public static readonly ReadOnlyCollection<string> AllRoles = [Administrator, Manager, User];
}