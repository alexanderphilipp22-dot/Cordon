using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cordon.Core;
using Cordon.Core.Audit;
using Cordon.Core.Configuration;

namespace Cordon.Cli;

/// <summary>
/// Prueft die HMAC-Kette des Audit-Logs.
/// <para>
/// Die Pruefung belegt, dass die Datei nicht nachtraeglich <i>stueckweise</i>
/// veraendert wurde: jede Zeile bindet den HMAC der Vorgaengerzeile ein.
/// Sie belegt <b>nicht</b>, dass ein Administrator die gesamte Datei nicht
/// konsistent neu erzeugt hat - das ist ausserhalb des Bedrohungsmodells.
/// </para>
/// </summary>
internal static class AuditVerifier
{
    public static int Verify(string directory)
    {
        if (!Directory.Exists(directory))
        {
            Console.Error.WriteLine($"Audit-Verzeichnis existiert nicht: {directory}");
            return 1;
        }

        AuditKeyStore.KeyResult keyResult;
        try
        {
            keyResult = AuditKeyStore.LoadOrCreate();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            Console.Error.WriteLine($"Audit-Schluessel nicht verfuegbar: {ex.Message}");
            return 1;
        }

        var files = Directory.GetFiles(directory, "cordon-*.jsonl")
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();
        if (files.Count == 0)
        {
            Console.Error.WriteLine("Keine Audit-Dateien gefunden.");
            return 1;
        }

        Console.WriteLine($"Schluessel: {keyResult.Description}");
        Console.WriteLine($"Dateien   : {files.Count}");
        Console.WriteLine();

        var previousHmac = string.Empty;
        var totalRecords = 0;
        var broken = 0;

        foreach (var file in files)
        {
            Console.WriteLine($"# {Path.GetFileName(file)}");

            var lineNumber = 0;

            foreach (var line in File.ReadLines(file))
            {
                lineNumber++;
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                AuditEvent? auditEvent;

                try
                {
                    auditEvent = JsonSerializer.Deserialize(line, CordonJsonContext.Default.AuditEvent);
                }
                catch (JsonException ex)
                {
                    Console.Error.WriteLine($"  Zeile {lineNumber}: ungueltiges JSON - {ex.Message}");
                    broken++;
                    continue;
                }

                if (auditEvent is null)
                {
                    broken++;
                    continue;
                }

                totalRecords++;

                var expectedPrevious = string.IsNullOrEmpty(previousHmac) ? null : previousHmac;
                if (!string.Equals(auditEvent.PrevHmac, expectedPrevious, StringComparison.Ordinal))
                {
                    Console.Error.WriteLine(
                        $"  Zeile {lineNumber} (seq {auditEvent.Seq}): prevHmac passt nicht. "
                        + $"Erwartet '{(expectedPrevious is null ? "<leer>" : expectedPrevious[..16] + "...")}', "
                        + $"gefunden '{(auditEvent.PrevHmac is null ? "<leer>" : auditEvent.PrevHmac[..16] + "...")}'.");
                    broken++;
                }

                var recomputed = ComputeHmac(keyResult.Key, previousHmac, auditEvent);
                if (!string.Equals(recomputed, auditEvent.Hmac, StringComparison.Ordinal))
                {
                    Console.Error.WriteLine(
                        $"  Zeile {lineNumber} (seq {auditEvent.Seq}): HMAC stimmt nicht - Eintrag wurde veraendert.");
                    broken++;
                }

                previousHmac = auditEvent.Hmac ?? string.Empty;
            }

            Console.WriteLine($"  {lineNumber} Zeile(n) geprueft.");
        }

        Console.WriteLine();
        Console.WriteLine($"Ergebnis: {totalRecords} Datensatz/Datensaetze, {broken} Abweichung(en).");

        if (broken == 0)
        {
            Console.WriteLine("Die Kette ist konsistent.");
            return 0;
        }

        Console.Error.WriteLine(
            "Die Kette ist NICHT konsistent. Das Audit kann nicht als unveraendert gelten.");
        return 1;
    }

    /// <summary>
    /// Muss exakt der Berechnung in <see cref="AuditLog"/> entsprechen.
    /// Die kanonische Form ist bewusst dupliziert statt geteilt: eine
    /// Aenderung an einer Stelle soll die Pruefung brechen lassen, statt
    /// stillschweigend beide Seiten mitzuziehen.
    /// </summary>
    private static string ComputeHmac(byte[] key, string previousHmac, AuditEvent e)
    {
        var canonical = Canonicalize(e);
        return Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(previousHmac + "\n" + canonical)));
    }

    private static string Canonicalize(AuditEvent e)
    {
        var sb = new StringBuilder(512);
        Append(sb, e.Seq.ToString(CultureInfo.InvariantCulture));
        Append(sb, e.Ts.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
        Append(sb, e.Event);
        Append(sb, e.AgentId);
        Append(sb, e.Identity?.Pid.ToString(CultureInfo.InvariantCulture));
        Append(sb, e.Identity?.ImagePath);
        Append(sb, e.Identity?.ImageSha256);
        Append(sb, e.Identity?.PackageSid);
        Append(sb, e.Identity?.Integrity);
        Append(sb, e.Identity?.IsAppContainer?.ToString(CultureInfo.InvariantCulture));
        Append(sb, e.Identity?.SignerSubject);

        if (e.Identity?.Capabilities is { Count: > 0 } capabilities)
        {
            foreach (var capability in capabilities.OrderBy(c => c, StringComparer.Ordinal))
            {
                Append(sb, capability);
            }
        }

        Append(sb, e.Target?.Kind);
        Append(sb, e.Target?.Host);
        Append(sb, e.Target?.RawHost);
        Append(sb, e.Target?.Port?.ToString(CultureInfo.InvariantCulture));
        Append(sb, e.Target?.Method);
        Append(sb, e.Target?.Path);
        Append(sb, e.Verdict);
        Append(sb, e.Code);
        Append(sb, e.Reason);
        Append(sb, e.ScopeId);
        Append(sb, e.CorrelationId);
        Append(sb, e.BytesUp?.ToString(CultureInfo.InvariantCulture));
        Append(sb, e.BytesDown?.ToString(CultureInfo.InvariantCulture));
        Append(sb, e.DurationMs?.ToString(CultureInfo.InvariantCulture));
        Append(sb, e.PrevHmac);

        if (e.Detail is not null)
        {
            foreach (var pair in e.Detail.OrderBy(p => p.Key, StringComparer.Ordinal))
            {
                Append(sb, pair.Key);
                Append(sb, pair.Value);
            }
        }

        return sb.ToString();
    }

    private static void Append(StringBuilder sb, string? value)
    {
        sb.Append(value ?? "\u0000");
        sb.Append('\u001f');
    }
}
