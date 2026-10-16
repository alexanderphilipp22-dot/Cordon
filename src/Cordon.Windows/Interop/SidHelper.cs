using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Cordon.Core;
using Cordon.Core.Model;

namespace Cordon.Windows.Interop;

/// <summary>
/// Umrechnung zwischen nativen SIDs und .NET-Objekten. Alle SIDs, die aus
/// einer P/Invoke stammen, muessen mit dem <b>zum Erzeuger passenden</b>
/// Aufruf freigegeben werden - <c>FreeSid</c> fuer <c>CreateWellKnownSid</c>-
/// artige Allokatoren, <c>LocalFree</c> fuer <c>ConvertStringSidToSid</c>.
/// </summary>
public static class SidHelper
{
    private static readonly Lazy<SecurityIdentifier> LowIntegritySid = new(() =>
        new SecurityIdentifier(WellKnownSidType.WinLowLabelSid, null));

    /// <summary>SID des Low-Integrity-Mandatory-Labels (<c>S-1-16-4096</c>).</summary>
    public static SecurityIdentifier LowMandatoryLabel => LowIntegritySid.Value;

    /// <summary>Formatiert eine native SID als String (<c>S-1-5-18</c>).</summary>
    public static string ToStringSid(IntPtr sid)
    {
        if (sid == IntPtr.Zero)
        {
            return string.Empty;
        }

        if (!NativeMethods.ConvertSidToStringSidW(sid, out var stringSid))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "ConvertSidToStringSidW fehlgeschlagen.");
        }

        try
        {
            return Marshal.PtrToStringUni(stringSid) ?? string.Empty;
        }
        finally
        {
            _ = NativeMethods.LocalFree(stringSid);
        }
    }

    /// <summary>Erzeugt eine native SID aus einem String. Aufrufer gibt mit <c>LocalFree</c> frei.</summary>
    public static IntPtr FromStringSid(string sid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sid);

        if (!NativeMethods.ConvertStringSidToSidW(sid, out var nativeSid))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                $"ConvertStringSidToSidW('{sid}') fehlgeschlagen.");
        }

        return nativeSid;
    }

    /// <summary>Liest die Integritaetsstufe aus einem <c>TOKEN_MANDATORY_LABEL</c>-SID.</summary>
    public static IntegrityLevel ReadIntegrityLevel(IntPtr mandatoryLabelSid)
    {
        if (mandatoryLabelSid == IntPtr.Zero || !NativeMethods.IsValidSid(mandatoryLabelSid))
        {
            return IntegrityLevel.Unknown;
        }

        var countPtr = NativeMethods.GetSidSubAuthorityCount(mandatoryLabelSid);
        if (countPtr == IntPtr.Zero)
        {
            return IntegrityLevel.Unknown;
        }

        var count = Marshal.ReadByte(countPtr);
        if (count == 0)
        {
            return IntegrityLevel.Unknown;
        }

        var ridPtr = NativeMethods.GetSidSubAuthority(mandatoryLabelSid, (uint)(count - 1));
        if (ridPtr == IntPtr.Zero)
        {
            return IntegrityLevel.Unknown;
        }

        var rid = Marshal.ReadInt32(ridPtr);

        return rid switch
        {
            < NativeMethods.SECURITY_MANDATORY_LOW_RID => IntegrityLevel.Untrusted,
            < NativeMethods.SECURITY_MANDATORY_MEDIUM_RID => IntegrityLevel.Low,
            < NativeMethods.SECURITY_MANDATORY_HIGH_RID => IntegrityLevel.Medium,
            < NativeMethods.SECURITY_MANDATORY_SYSTEM_RID => IntegrityLevel.High,
            _ => IntegrityLevel.System,
        };
    }
}
