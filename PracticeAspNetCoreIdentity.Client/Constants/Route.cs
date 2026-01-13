namespace PracticeAspNetCoreIdentity.Client.Constants;

public static class Route
{
    public const string NotFound = "/not-found";
    public const string Home = "/";
    public const string Login = "/login";
    public const string Register = "/register";
    public const string ForgotPassword = "/forgot-password";
    public const string ConfirmEmail = "/confirm-email";
    
    public const string SetPassword = "/set-password";
    public const string ChangePassword = "/change-password";

    public const string AdminAllAccounts = "/admin/all-accounts";
    public const string AdminAccountDetail = "/admin/account-detail";

    public const string AddNote = "/add-note";
    public const string UpdateNote = "/update-note";
    public const string AllNotes = "/all-notes";
}