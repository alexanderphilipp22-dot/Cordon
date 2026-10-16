using Cordon.Core;
using Cordon.Core.Model;
using Cordon.Core.Policy;

namespace Cordon.Windows;

/// <summary>Ergebnis der Identitaetsvalidierung.</summary>
public sealed record IdentityValidationResult(
    bool IsAuthorized,
    IReadOnlyList<string> Violations,
    IReadOnlyList<string> Warnings)
{
    public string Summary => IsAuthorized
        ? "Identitaet bestaetigt."
        : string.Join(" | ", Violations);

    /// <summary>Alle Meldungen, auch die nicht blockierenden.</summary>
    public string FullSummary =>
        string.Join(" | ", Violations.Concat(Warnings));
}

/// <summary>
/// Erzwingt die Invarianten, die ein Agent erfuellen <b>muss</b>. Jede
/// einzelne davon ist eine eigenstaendige Sicherheitszusage; die Pruefung
/// sammelt bewusst <i>alle</i> Verstoesse statt beim ersten abzubrechen,
/// damit ein Audit zeigt, wie weit ein Angreifer gekommen ist.
/// </summary>
public static class IdentityValidator
{
    public static IdentityValidationResult Validate(
        ClientIdentity identity,
        bool requireAppContainer = true,
        bool requireLowIntegrity = true,
        IReadOnlyList<string>? allowedCapabilities = null)
    {
        ArgumentNullException.ThrowIfNull(identity);

        var violations = new List<string>();
        var warnings = new List<string>();

        if (identity.Pid == 0)
        {
            violations.Add("PID 0 ist kein gueltiger Aufrufer.");
        }

        if (string.IsNullOrWhiteSpace(identity.ImagePath))
        {
            violations.Add("Image-Pfad konnte nicht ermittelt werden.");
        }

        if (requireAppContainer && !identity.IsAppContainer)
        {
            violations.Add(
                "Aufrufer ist kein AppContainer. Die Netzwerkgrenze wird ausschliesslich "
                + "vom AppContainer-Layer durchgesetzt und kann ohne ihn nicht garantiert werden.");
        }

        if (requireLowIntegrity)
        {
            // Unknown wird ABGELEHNT, nicht durchgelassen. Ein unbestaetigtes
            // Integritaetslevel ist keine Eigenschaft, sondern eine fehlende
            // Aussage - und eine fehlende Aussage darf keine Zusage ersetzen.
            // Ohne diese Zeile waere die Integritaetsanforderung umgehbar,
            // indem man die Abfrage zum Scheitern bringt.
            if (identity.Integrity == IntegrityLevel.Unknown)
            {
                violations.Add(
                    "Integritaetslevel konnte nicht ermittelt werden. Ein unbestaetigtes "
                    + "Level erfuellt die Anforderung nicht (fail closed).");
            }
            else if (identity.Integrity is IntegrityLevel.Medium
                or IntegrityLevel.High or IntegrityLevel.System or IntegrityLevel.Protected)
            {
                violations.Add(
                    $"Integritaetslevel {identity.Integrity} ist zu hoch fuer einen Agenten "
                    + "(erwartet: Low oder Untrusted).");
            }
        }

        CheckCapabilities(identity, allowedCapabilities, violations);
        CheckPackageSid(identity, violations);
        CheckImagePath(identity, violations, warnings);

        return new IdentityValidationResult(violations.Count == 0, violations, warnings);
    }

    /// <summary>
    /// Kein Agent darf eine Netzwerk-Capability besitzen. Diese Pruefung ist
    /// die Versicherung gegen eine Fehlkonfiguration beim Start: wenn
    /// <c>internetClient</c> im Token landet, ist die primaere Grenze weg,
    /// und Cordon faellt dann auf die WFP-Regel (falls aktiv) zurueck.
    /// </summary>
    private static void CheckCapabilities(
        ClientIdentity identity,
        IReadOnlyList<string>? allowedCapabilities,
        List<string> violations)
    {
        if (identity.Capabilities.Count == 0)
        {
            return;
        }

        var allowlist = allowedCapabilities ?? [];

        foreach (var capability in identity.Capabilities)
        {
            var permitted = false;
            foreach (var allowed in allowlist)
            {
                if (string.Equals(allowed, capability, StringComparison.OrdinalIgnoreCase))
                {
                    permitted = true;
                    break;
                }
            }

            if (!permitted)
            {
                violations.Add(
                    $"Token besitzt die nicht erlaubte Capability '{capability}'. "
                    + "Jede Capability kann die Netzwerkgrenze aufheben.");
            }
        }
    }

    /// <summary>
    /// Kreuz-Check der Package-SID gegen die Erwartung der Pipe-Instanz.
    /// <para>
    /// Die DACL der Pipe sollte bereits verhindern, dass ein anderer
    /// AppContainer verbindet. Dieser Check ist die <b>zweite, unabhaengige
    /// Bindung</b>: er erkennt eine fehlerhaft gesetzte DACL, statt sich auf
    /// sie zu verlassen.
    /// </para>
    /// </summary>
    private static void CheckPackageSid(ClientIdentity identity, List<string> violations)
    {
        if (string.IsNullOrWhiteSpace(identity.ExpectedPackageSid))
        {
            // Ohne Erwartung gaebe es keine zweite Bindung. Das ist ein
            // Konfigurationsfehler der Pipe-Instanz und wird abgelehnt.
            violations.Add("Pipe-Instanz hat keine erwartete Package-SID.");
            return;
        }

        if (string.IsNullOrWhiteSpace(identity.PackageSid))
        {
            violations.Add("Token lieferte keine Package-SID.");
            return;
        }

        if (!string.Equals(identity.PackageSid, identity.ExpectedPackageSid, StringComparison.OrdinalIgnoreCase))
        {
            violations.Add(
                $"Package-SID des Tokens ('{identity.PackageSid}') entspricht nicht der "
                + $"erwarteten SID ('{identity.ExpectedPackageSid}').");
        }
    }

    /// <summary>
    /// Das Image muss unter dem erwarteten Pfad liegen. Der Vergleich nutzt
    /// <see cref="PolicyEngine.PathStartsWith"/> und damit eine erzwungene
    /// Verzeichnisgrenze - sonst wuerde <c>C:\Agents\res</c> auch
    /// <c>C:\Agents\research-evil\</c> erfassen.
    /// <para>
    /// Ist ein Root konfiguriert und passt nicht, ist das ein
    /// <b>Verstoss</b> (fail closed). Ist gar kein Root konfiguriert, ist das
    /// eine Warnung: der Agent bleibt nutzbar, aber mit einer Bindung
    /// weniger. Diese Trennung ist wichtig - ein fehlkonfigurierter Root darf
    /// nicht stillschweigend zum Wegfall der Pruefung fuehren.
    /// </para>
    /// </summary>
    private static void CheckImagePath(
        ClientIdentity identity,
        List<string> violations,
        List<string> warnings)
    {
        if (string.IsNullOrWhiteSpace(identity.ExpectedImagePath))
        {
            warnings.Add(
                "Kein imageRoots im Scope: die Image-Pfad-Bindung fehlt. Die Identitaet "
                + "stuetzt sich allein auf Pipe-DACL und Package-SID.");
            return;
        }

        if (!PolicyEngine.PathStartsWith(identity.ImagePath, identity.ExpectedImagePath))
        {
            violations.Add(
                $"Image-Pfad '{identity.ImagePath}' liegt nicht unter dem erwarteten "
                + $"Pfad '{identity.ExpectedImagePath}'.");
        }
    }
}
