namespace Cordon.Core.Configuration;

/// <summary>
/// Zentrale Pfade. Alle Cordon-Daten liegen unter
/// <c>%ProgramData%\Cordon</c>, damit sie unabhaengig vom Benutzerprofil
/// ACL-geschuetzt werden koennen.
/// </summary>
public static class CordonPaths
{
    public const string ProductName = "Cordon";

    public const string ServiceName = "CordonControl";

    public const string ServiceDisplayName = "Cordon Control";

    public const string AuditHmacKeyFileName = "audit-hmac.key";

    public const string ScopesFileName = "scopes.json";

    public const string CaDirectoryName = "ca";

    public static string RootDirectory { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        ProductName);

    public static string ConfigDirectory => Path.Combine(RootDirectory, "config");

    public static string AuditDirectory => Path.Combine(RootDirectory, "audit");

    public static string StateDirectory => Path.Combine(RootDirectory, "state");

    public static string CaDirectory => Path.Combine(RootDirectory, CaDirectoryName);

    public static string ScopesFile => Path.Combine(ConfigDirectory, ScopesFileName);

    public static string AuditHmacKeyFile => Path.Combine(ConfigDirectory, AuditHmacKeyFileName);

    public static string SandboxProfilesFile => Path.Combine(StateDirectory, "sandbox-profiles.json");

    /// <summary>Alle Verzeichnisse, die Cordon erwartet.</summary>
    public static IReadOnlyList<string> AllDirectories =>
    [
        RootDirectory,
        ConfigDirectory,
        AuditDirectory,
        StateDirectory,
        CaDirectory,
    ];
}
