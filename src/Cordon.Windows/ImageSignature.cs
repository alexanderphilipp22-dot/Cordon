using System.Runtime.InteropServices;
using Cordon.Windows.Interop;

namespace Cordon.Windows;

/// <summary>
/// P/Invoke fuer Authenticode-Pruefung und SHA-256-Bildung eines Images.
/// </summary>
internal static class SignatureNative
{
    internal const uint WTD_UI_NONE = 2;

    internal const uint WTD_REVOKE_NONE = 0;

    internal const uint WTD_CHOICE_FILE = 1;

    internal const uint WTD_STATEACTION_VERIFY = 1;

    internal const uint WTD_STATEACTION_CLOSE = 2;

    internal const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;

    internal const uint WTD_DISABLE_MD2_MD4 = 0x00002000;

    internal const uint WTD_REVOCATION_CHECK_NONE = 0x00000010;

    /// <summary>Der generische Authenticode-Aktionsbezeichner.</summary>
    internal static readonly Guid WinTrustActionGenericVerifyV2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WINTRUST_FILE_INFO
    {
        internal uint cbStruct;
        internal IntPtr pcwszFilePath;
        internal IntPtr hFile;
        internal IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WINTRUST_DATA
    {
        internal uint cbStruct;
        internal IntPtr pPolicyCallbackData;
        internal IntPtr pSIPClientData;
        internal uint dwUIChoice;
        internal uint fdwRevocationChecks;
        internal uint dwUnionChoice;
        internal IntPtr pFile;
        internal uint dwStateAction;
        internal IntPtr hWVTStateData;
        internal IntPtr pwszURLReference;
        internal uint dwProvFlags;
        internal uint dwUIContext;
        internal IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern int WinVerifyTrust(
        IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid actionId,
        IntPtr data);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptQueryObject(
        uint objectType,
        IntPtr pvObject,
        uint expectedContentTypeFlags,
        uint expectedFormatTypeFlags,
        uint flags,
        out uint messageAndCertEncodingType,
        out uint contentType,
        out uint formatType,
        out IntPtr certStore,
        out IntPtr message,
        out IntPtr context);

    // --- Zertifikats-Extraktion (Signer-Subject) -------------------------

    internal const uint CERT_QUERY_OBJECT_FILE = 0x00000001;

    internal const uint CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 0x00000400;

    internal const uint CERT_QUERY_FORMAT_FLAG_BINARY = 0x00000002;

    /// <summary>Vollstaendiger Subject-RDN (z. B. "CN=...", "O=...").</summary>
    internal const uint CERT_NAME_RDN_TYPE = 2;

    [DllImport("crypt32.dll", SetLastError = true)]
    internal static extern IntPtr CertEnumCertificatesInStore(
        IntPtr hCertStore,
        IntPtr pPrevCertContext);

    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern uint CertGetNameStringW(
        IntPtr pCertContext,
        uint dwType,
        uint dwFlags,
        IntPtr pvTypePara,
        [Out] char[]? pszNameString,
        uint cchNameString);

    [DllImport("crypt32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CertFreeCertificateContext(IntPtr pCertContext);

    [DllImport("crypt32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CertCloseStore(IntPtr hCertStore, uint dwFlags);

    [DllImport("crypt32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptMsgClose(IntPtr hCryptMsg);
}

/// <summary>
/// Prueft die Authenticode-Signatur eines Agent-Images und liest den
/// Subject des Signaturzertifikats aus.
/// </summary>
public static class ImageSignature
{
    /// <summary>Ergebnis einer Signaturpruefung.</summary>
    public sealed record Result(bool IsTrusted, string? SignerSubject, string? Error)
    {
        public static Result Trusted(string? subject) => new(true, subject, null);

        public static Result Untrusted(string error) => new(false, null, error);
    }

    /// <summary>
    /// Prueft die Signatur. <b>Keine</b> Online-Revocation-Pruefung
    /// (<c>WTD_CACHE_ONLY_URL_RETRIEVAL</c>): eine Pruefung, die auf das
    /// Netz wartet, wuerde den Agentenstart blockieren, wenn das Netz
    /// gerade nicht erreichbar ist - und der Agent soll ja gerade <i>nicht</i>
    /// vom Netz abhaengen.
    /// </summary>
    public static Result Verify(string imagePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(imagePath);

        if (!File.Exists(imagePath))
        {
            return Result.Untrusted($"Image existiert nicht: {imagePath}");
        }

        var filePathPointer = Marshal.StringToHGlobalUni(imagePath);
        var fileInfoPointer = IntPtr.Zero;

        try
        {
            var fileInfo = new SignatureNative.WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<SignatureNative.WINTRUST_FILE_INFO>(),
                pcwszFilePath = filePathPointer,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero,
            };

            fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<SignatureNative.WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, fDeleteOld: false);

            var data = new SignatureNative.WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<SignatureNative.WINTRUST_DATA>(),
                dwUIChoice = SignatureNative.WTD_UI_NONE,
                fdwRevocationChecks = SignatureNative.WTD_REVOKE_NONE,
                dwUnionChoice = SignatureNative.WTD_CHOICE_FILE,
                pFile = fileInfoPointer,
                dwStateAction = SignatureNative.WTD_STATEACTION_VERIFY,
                dwProvFlags = SignatureNative.WTD_REVOCATION_CHECK_NONE
                    | SignatureNative.WTD_CACHE_ONLY_URL_RETRIEVAL
                    | SignatureNative.WTD_DISABLE_MD2_MD4,
            };

            var dataPointer = Marshal.AllocHGlobal(Marshal.SizeOf<SignatureNative.WINTRUST_DATA>());
            try
            {
                Marshal.StructureToPtr(data, dataPointer, fDeleteOld: false);

                var result = SignatureNative.WinVerifyTrust(
                    IntPtr.Zero,
                    SignatureNative.WinTrustActionGenericVerifyV2,
                    dataPointer);

                // Der State muss in jedem Fall geschlossen werden, sonst
                // bleibt Systemspeicher belegt.
                if (result != 0)
                {
                    return Result.Untrusted(
                        $"WinVerifyTrust lieferte 0x{result:X8} ({DescribeTrustError(result)}).");
                }

                // Kette ist gueltig: Signer-Subject aus dem Zertifikat lesen.
                // Gelingt das nicht, wird <c>null</c> zurueckgegeben - der
                // Aufrufer muss dann fail-closed entscheiden (kein Subject =
                // keine Freigabe).
                return Result.Trusted(TryGetSignerSubject(imagePath));
            }
            finally
            {
                data.dwStateAction = SignatureNative.WTD_STATEACTION_CLOSE;
                Marshal.StructureToPtr(data, dataPointer, fDeleteOld: false);
                _ = SignatureNative.WinVerifyTrust(
                    IntPtr.Zero,
                    SignatureNative.WinTrustActionGenericVerifyV2,
                    dataPointer);

                Marshal.FreeHGlobal(dataPointer);
            }
        }
        finally
        {
            if (fileInfoPointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(fileInfoPointer);
            }

            Marshal.FreeHGlobal(filePathPointer);
        }
    }

    /// <summary>
    /// Liest den Subject des Signaturzertifikats eines Authenticode-signierten
    /// Images aus. Gibt <c>null</c> zurueck, wenn kein Zertifikat ermittelt
    /// werden kann - der Aufrufer muss dann fail-closed entscheiden.
    /// </summary>
    private static string? TryGetSignerSubject(string imagePath)
    {
        var filePathPointer = Marshal.StringToHGlobalUni(imagePath);
        IntPtr certStore = IntPtr.Zero;
        IntPtr message = IntPtr.Zero;

        try
        {
            if (!SignatureNative.CryptQueryObject(
                    SignatureNative.CERT_QUERY_OBJECT_FILE,
                    filePathPointer,
                    SignatureNative.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                    SignatureNative.CERT_QUERY_FORMAT_FLAG_BINARY,
                    0,
                    out _,
                    out _,
                    out _,
                    out certStore,
                    out message,
                    out _))
            {
                return null;
            }

            try
            {
                var certContext = SignatureNative.CertEnumCertificatesInStore(certStore, IntPtr.Zero);
                if (certContext == IntPtr.Zero)
                {
                    return null;
                }

                try
                {
                    // Zuerst die benoetigte Puffergroesse (inkl. Null-Terminator)
                    // ermitteln, dann den Namen in einem zweiten Aufruf lesen.
                    var required = SignatureNative.CertGetNameStringW(
                        certContext,
                        SignatureNative.CERT_NAME_RDN_TYPE,
                        0,
                        IntPtr.Zero,
                        null,
                        0);

                    if (required <= 1)
                    {
                        return null;
                    }

                    var buffer = new char[required];
                    var written = SignatureNative.CertGetNameStringW(
                        certContext,
                        SignatureNative.CERT_NAME_RDN_TYPE,
                        0,
                        IntPtr.Zero,
                        buffer,
                        required);

                    if (written <= 1)
                    {
                        return null;
                    }

                    // written enthaelt den Null-Terminator.
                    return new string(buffer, 0, (int)written - 1).Trim();
                }
                finally
                {
                    SignatureNative.CertFreeCertificateContext(certContext);
                }
            }
            finally
            {
                SignatureNative.CertCloseStore(certStore, 0);
            }
        }
        finally
        {
            if (message != IntPtr.Zero)
            {
                SignatureNative.CryptMsgClose(message);
            }

            Marshal.FreeHGlobal(filePathPointer);
        }
    }

    /// <summary>Kurzbeschreibung bekannter Trust-Fehlercodes.</summary>
    private static string DescribeTrustError(int result) => result switch
    {
        unchecked((int)0x800B0100) => "TRUST_E_NOSIGNATURE: keine Signatur vorhanden",
        unchecked((int)0x800B0101) => "CERT_E_EXPIRED: Zertifikat abgelaufen",
        unchecked((int)0x800B0109) => "CERT_E_UNTRUSTEDROOT: Wurzel nicht vertrauenswuerdig",
        unchecked((int)0x800B010A) => "CERT_E_CHAINING: Kette nicht aufloesbar",
        unchecked((int)0x800B010C) => "TRUST_E_EXPLICIT_DISTRUST: Signatur explizit misstraut",
        unchecked((int)0x80096010) => "TRUST_E_BAD_DIGEST: Inhalt nach Signatur veraendert",
        _ => "unbekannter Trust-Fehler",
    };
}

/// <summary>
/// Bildet den SHA-256-Hash eines Images.
/// <para>
/// Ein laufendes Image ist exklusiv geoeffnet. Deshalb wird zuerst mit
/// vollstaendigem Sharing geoeffnet; schlaegt das fehl, wird das Image in
/// eine temporaere Datei kopiert und die Kopie gehasht. Ohne diesen
/// Fallback waere <c>imageSha256</c> fuer python.exe/node.exe praktisch
/// immer leer und damit als Audit-Feld wertlos.
/// </para>
/// </summary>
public static class ImageHasher
{
    /// <summary>Berechnet den Hash. Gibt <c>null</c> zurueck, wenn das Image
    /// nicht lesbar ist - ein fehlender Hash darf den Start nicht verhindern,
    /// solange keine Signaturpflicht besteht.</summary>
    public static string? TryComputeSha256(string imagePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(imagePath);

        try
        {
            return ComputeDirect(imagePath);
        }
        catch (IOException)
        {
            // Faellt unten auf die Kopie zurueck.
        }
        catch (UnauthorizedAccessException)
        {
            // dito
        }

        try
        {
            return ComputeFromCopy(imagePath);
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static string ComputeDirect(string imagePath)
    {
        using var stream = new FileStream(
            imagePath,
            FileMode.Open,
            FileAccess.Read,
            // Vollstaendiges Sharing: das Image darf gleichzeitig laufen.
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 1024 * 1024,
            FileOptions.SequentialScan);

        using var sha = System.Security.Cryptography.SHA256.Create();
        var hash = sha.ComputeHash(stream);
        return Convert.ToHexString(hash);
    }

    private static string ComputeFromCopy(string imagePath)
    {
        var temporary = Path.Combine(
            Path.GetTempPath(),
            $"cordon-hash-{Guid.NewGuid():N}.tmp");

        try
        {
            File.Copy(imagePath, temporary, overwrite: true);

            using var stream = new FileStream(
                temporary,
                FileMode.Open,
                FileAccess.Read,
                FileShare.None,
                bufferSize: 1024 * 1024,
                FileOptions.SequentialScan | FileOptions.DeleteOnClose);

            using var sha = System.Security.Cryptography.SHA256.Create();
            var hash = sha.ComputeHash(stream);
            return Convert.ToHexString(hash);
        }
        finally
        {
            TryDelete(temporary);
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
            // DeleteOnClose raeumt spaeter auf.
        }
        catch (UnauthorizedAccessException)
        {
            // dito
        }
    }
}
