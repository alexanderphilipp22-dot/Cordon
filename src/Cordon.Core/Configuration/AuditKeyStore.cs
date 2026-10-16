using System.Security.Cryptography;

namespace Cordon.Core.Configuration;

/// <summary>
/// Verwaltet den schluesselabhaengigen Schutz des HMAC-Schluessels fuer das Audit-Log.
/// Der Schluessel wird mittels Windows DPAPI (LocalMachine) verschluesselt abgelegt.
/// </summary>
public static class AuditKeyStore
{
    public sealed record KeyResult(byte[] Key, string Description);

    /// <summary>
    /// Laedt den vorhandenen HMAC-Schluessel oder erzeugt einen neuen 256-Bit-Schluessel.
    /// </summary>
    public static KeyResult LoadOrCreate(string? path = null)
    {
        var filePath = path ?? CordonPaths.AuditHmacKeyFile;
        var dir = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }

        if (File.Exists(filePath))
        {
            byte[] encrypted;
            try
            {
                encrypted = File.ReadAllBytes(filePath);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                throw;
            }

            try
            {
                var decrypted = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.LocalMachine);

                // Ein gueltiger HMAC-SHA256-Schluessel muss mindestens 32 Byte
                // liefern. Eine kuerzere Entschluesselung deutet auf eine
                // beschraedigte oder manipulierte Datei hin -> fail closed.
                if (decrypted.Length < 32)
                {
                    throw new InvalidOperationException(
                        $"Der entschluesselte Audit-Schluessel hat eine ungueltige Laenge "
                        + $"({decrypted.Length} Byte; mindestens 32 erwartet).");
                }

                return new KeyResult(decrypted, $"Vorhanden ({filePath}, DPAPI LocalMachine)");
            }
            catch (CryptographicException ex)
            {
                throw new InvalidOperationException($"DPAPI-Entschluesselung fehlgeschlagen: {ex.Message}", ex);
            }
        }

        var key = new byte[32];
        RandomNumberGenerator.Fill(key);

        byte[] protectedBytes;
        try
        {
            protectedBytes = ProtectedData.Protect(key, null, DataProtectionScope.LocalMachine);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException($"DPAPI-Verschluesselung fehlgeschlagen: {ex.Message}", ex);
        }

        File.WriteAllBytes(filePath, protectedBytes);
        return new KeyResult(key, $"Neu erzeugt ({filePath}, DPAPI LocalMachine)");
    }
}