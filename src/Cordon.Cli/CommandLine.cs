using System.Globalization;

namespace Cordon.Cli;

/// <summary>
/// Minimaler Optionsparser. Bewusst handgeschrieben statt ueber eine
/// Bibliothek: das CLI ist ein Sicherheitswerkzeug, und die Anzahl der
/// Abhaengigkeiten soll klein bleiben (u. a. damit der Build offline
/// funktioniert).
/// </summary>
internal sealed class CommandLine
{
    private readonly Dictionary<string, string> _values = new(StringComparer.Ordinal);
    private readonly HashSet<string> _flags = new(StringComparer.Ordinal);

    private CommandLine()
    {
    }

    public static CommandLine Parse(string[] args)
    {
        var result = new CommandLine();

        for (var i = 0; i < args.Length; i++)
        {
            var argument = args[i];
            if (!argument.StartsWith("--", StringComparison.Ordinal))
            {
                continue;
            }

            var equals = argument.IndexOf('=', StringComparison.Ordinal);
            if (equals > 0)
            {
                result._values[argument[..equals]] = argument[(equals + 1)..];
                continue;
            }

            // Ist der naechste Wert ein Argument dieses Schalters?
            if (i + 1 < args.Length && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
            {
                result._values[argument] = args[i + 1];
                i++;
                continue;
            }

            result._flags.Add(argument);
        }

        return result;
    }

    public bool Has(string name) => _flags.Contains(name) || _values.ContainsKey(name);

    public string? Get(string name) => _values.TryGetValue(name, out var value) ? value : null;

    public TimeSpan GetSeconds(string name, double fallback)
    {
        var raw = Get(name);
        if (raw is null)
        {
            return TimeSpan.FromSeconds(fallback);
        }

        return double.TryParse(raw, NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds)
            ? TimeSpan.FromSeconds(seconds)
            : TimeSpan.FromSeconds(fallback);
    }
}

/// <summary>
/// Hilfsfunktionen fuer Kommandos, bei denen nach einem Trennzeichen
/// (<c>--</c>) ein fremder Befehl mit eigenen Schaltern folgt.
/// </summary>
internal static class OptionParser
{
    /// <summary>
    /// Liest einen Schalterwert und gibt den Rumpf ohne diesen Schalter
    /// zurueck. Wird verwendet, wenn Optionen und ein Fremdbefehl im selben
    /// Array stehen und die Optionen <b>vor</b> dem Trennzeichen liegen.
    /// </summary>
    public static string? TakeValue(string[] args, string name, out string[] remaining)
    {
        ArgumentNullException.ThrowIfNull(args);

        var result = new List<string>(args.Length);
        string? value = null;

        for (var i = 0; i < args.Length; i++)
        {
            if (args[i] == "--")
            {
                result.AddRange(args.Skip(i));
                break;
            }

            if (string.Equals(args[i], name, StringComparison.Ordinal) && i + 1 < args.Length)
            {
                value = args[i + 1];
                i++;
                continue;
            }

            var prefix = name + "=";
            if (args[i].StartsWith(prefix, StringComparison.Ordinal))
            {
                value = args[i][prefix.Length..];
                continue;
            }

            result.Add(args[i]);
        }

        remaining = [.. result];
        return value;
    }

    public static int TakeInt(string[] args, string name, int fallback) =>
        int.TryParse(TakeValue(args, name, out _), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            ? value
            : fallback;

    public static long TakeLong(string[] args, string name, long fallback) =>
        long.TryParse(TakeValue(args, name, out _), NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            ? value
            : fallback;

    /// <summary>
    /// Trennt Optionen von dem auszufuehrenden Befehl. Alles nach dem ersten
    /// <c>--</c> gehoert dem Agenten und wird <b>nicht</b> interpretiert -
    /// sonst koennte ein Agentenargument wie <c>--no-wfp</c> Cordons eigene
    /// Konfiguration veraendern.
    /// </summary>
    public static IReadOnlyList<string> SplitCommand(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        var separator = Array.IndexOf(args, "--");
        var command = separator >= 0 ? args[(separator + 1)..] : args;

        // Optionen vor dem Trenner beginnen mit '--' und werden verworfen.
        // Alles andere gilt als Befehl (Kompatibilitaet fuer den Fall, dass
        // kein Trenner verwendet wurde).
        return separator >= 0
            ? command
            : [.. command.Where(a => !a.StartsWith("--", StringComparison.Ordinal))];
    }
}
