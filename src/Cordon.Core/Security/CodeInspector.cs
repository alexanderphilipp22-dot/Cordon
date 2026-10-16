using System.Text.RegularExpressions;

namespace Cordon.Core.Security;

/// <summary>Ein einzelner Treffer in einer geprüften Code-Payload.</summary>
public sealed record CodeFinding(string RuleId, int Line, string Reason)
{
    public override string ToString() => $"{RuleId} (Zeile {Line}): {Reason}";
}

/// <summary>Ergebnis einer statischen Code-Inspektion.</summary>
public sealed record CodeInspectionResult(bool IsAllowed, IReadOnlyList<CodeFinding> Findings)
{
    public static CodeInspectionResult Allow() => new(true, []);

    public static CodeInspectionResult Deny(IReadOnlyList<CodeFinding> findings) => new(false, findings);
}

/// <summary>
/// Eine verbotene Code-Struktur: ein kompiliertes Regex-Muster plus Begründung.
/// </summary>
public sealed class CodeInspectionRule
{
    public CodeInspectionRule(string id, string pattern, string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(id);
        ArgumentException.ThrowIfNullOrWhiteSpace(pattern);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);

        Id = id;
        Reason = reason;
        Pattern = new Regex(
            pattern,
            RegexOptions.Compiled
                | RegexOptions.CultureInvariant
                | RegexOptions.IgnoreCase);
    }

    public string Id { get; }

    public Regex Pattern { get; }

    public string Reason { get; }
}

/// <summary>
/// Statische Analyse von dynamisch generiertem Python-/JavaScript-Code.
/// <para>
/// Die Prüfung ist bewusst konservativ und fail-closed: jeder Treffer einer
/// verbotenen Struktur blockiert die Ausführung <b>vor</b> der
/// Job-Object-Startphase. Die Regeln sind einfache, deterministische
/// Regex-Muster und damit transparent und ohne zusätzliche Laufzeitabhängigkeit
/// auditierbar.
/// </para>
/// </summary>
public static class CodeInspector
{
    /// <summary>
    /// Prüft eine Code-Payload zeilenweise gegen die übergebenen Regeln.
    /// Liefert alle Treffer; <see cref="CodeInspectionResult.IsAllowed"/> ist nur
    /// dann <c>true</c>, wenn keine Regel greift.
    /// </summary>
    public static CodeInspectionResult Inspect(string source, IReadOnlyList<CodeInspectionRule> rules)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(rules);

        if (source.Length == 0 || rules.Count == 0)
        {
            return CodeInspectionResult.Allow();
        }

        var lines = source.Split('\n');
        var findings = new List<CodeFinding>();

        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            foreach (var rule in rules)
            {
                if (rule.Pattern.IsMatch(line))
                {
                    findings.Add(new CodeFinding(rule.Id, i + 1, rule.Reason));
                }
            }
        }

        return findings.Count == 0
            ? CodeInspectionResult.Allow()
            : CodeInspectionResult.Deny(findings);
    }

    /// <summary>Vorgefertigte Python-Regeln (rohe Sockets, ctypes, Subprozesse, …).</summary>
    public static IReadOnlyList<CodeInspectionRule> DefaultPythonRules { get; } =
    [
        Rule("python_raw_socket", @"\b(import\s+socket|from\s+socket\s+import)\b",
            "Rohe Socket-Nutzung umgeht die AppContainer-Netzwerkgrenze."),
        Rule("python_ctypes", @"\b(import\s+ctypes|from\s+ctypes\s+import)\b",
            "ctypes erlaubt direkte native System-API-Aufrufe."),
        Rule("python_subprocess", @"\b(import\s+subprocess|subprocess\.(run|Popen|call|check_output)|os\.(system|popen|spawnv?))\b",
            "Ungeprüfter Subprozess-Aufruf ausserhalb der Job-Object-Kette."),
        Rule("python_registry", @"\b(import\s+(winreg|_winreg)|winreg\.)",
            "Registry-Modifikation ist nicht zulässig."),
        Rule("python_dynamic_exec", @"\b(eval|exec|compile)\s*\(",
            "Dynamische Code-Ausführung zur Laufzeit."),
        Rule("python_deserialize", @"\b(import\s+pickle|pickle\.(loads|load))\b",
            "Unsichere Deserialisierung (Pickle)."),
        Rule("python_dynamic_import", @"\b(__import__|importlib\.import_module)\s*\(",
            "Dynamischer Import umgeht die statische Pruefung."),
    ];

    /// <summary>Vorgefertigte JavaScript-Regeln (Subprozesse, rohe Sockets, eval).</summary>
    public static IReadOnlyList<CodeInspectionRule> DefaultJavaScriptRules { get; } =
    [
        Rule("js_child_process", @"\b(require\s*\(\s*['""]child_process['""]\s*\)|child_process\.(exec|spawn|fork))",
            "Ungeprüfter Subprozess-Aufruf (child_process)."),
        Rule("js_raw_socket", @"\b(require\s*\(\s*['""]net['""]\s*\)|net\.Socket\b)",
            "Rohe Socket-Nutzung umgeht die Netzwerkgrenze."),
        Rule("js_dynamic_exec", @"\b(eval\s*\(|new\s+Function\b)",
            "Dynamische Code-Ausführung (eval / Function-Konstruktor)."),
        Rule("js_dynamic_import", @"\bimport\s*\(",
            "Dynamischer Import umgeht die statische Pruefung."),
    ];

    private static CodeInspectionRule Rule(string id, string pattern, string reason) =>
        new(id, pattern, reason);
}
