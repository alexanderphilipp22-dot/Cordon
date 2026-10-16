using System.Runtime.InteropServices;

namespace Cordon.Windows.Interop;

/// <summary>
/// P/Invoke-Deklarationen der Windows Filtering Platform (WFP).
/// <para>
/// <b>Warum flache API statt COM:</b> <c>FwpmFilterAdd0</c> und
/// <c>FwpmEngineOpen0</c> sind die dokumentierten flachen Einstiegspunkte in
/// <c>fwpuclnt.dll</c>. Die COM-Schnittstelle (<c>FwpmFilterAdd0</c> ueber
/// <c>BFE</c>) waere hier nur ein zusaetzlicher Marshalling-Layer ohne
/// Sicherheitsgewinn.
/// </para>
/// <para>
/// <b>Layout-Abhaengigkeit:</b> Die Structs bilden die x64-Anordnung der
/// Windows-Header ab. Fuer x86 waeren UIntPtr-basierte Felder 4 Byte und
/// muessten getrennt geprueft werden; Cordon zielt auf x64, und
/// <see cref="WfpEnforcement"/> prueft das zur Laufzeit.
/// </para>
/// </summary>
internal static class WfpNative
{
    internal const uint FWP_E_SUCCESS = 0;

    /// <summary>FWPM_SESSION_FLAG_DYNAMIC: die Session (und damit alle
    /// dynamischen Filter) endet mit dem Prozess.</summary>
    internal const uint FWPM_SESSION_FLAG_DYNAMIC = 0x00000001;

    internal const uint FWP_ACTION_FLAG_TERMINATING = 0x00001000;

    internal const uint FWP_ACTION_FLAG_NON_TERMINATING = 0x00002000;

    internal const uint FWP_ACTION_BLOCK = 0x00000001 | FWP_ACTION_FLAG_TERMINATING;

    internal const uint FWP_ACTION_PERMIT = 0x00000002 | FWP_ACTION_FLAG_TERMINATING;

    internal const uint FWP_EMPTY = 0x00000000;

    internal const uint FWP_BYTE_BLOB_TYPE = 0x00000009;

    internal const uint FWP_UINT64 = 0x00000004;

    internal const uint FWP_MATCH_EQUAL = 0;

    internal const uint FWPM_FILTER_FLAG_PERSISTENT = 0x00000001;

    internal const uint FWPM_FILTER_FLAG_BOOTTIME = 0x00000002;

    internal const uint FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT = 0x00000004;

    /// <summary>
    /// Blockierendes Filtergewicht. Der Wert liegt im Bereich der
    /// reservierten Gewichte fuer "Block"-Filter und schlaegt damit
    /// gewoehnliche Permit-Filter.
    /// </summary>
    internal const ulong BlockWeight = 0x0000000000000001;

    [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    internal static extern uint FwpmEngineOpen0(
        string? serverName,
        uint authnService,
        IntPtr authIdentity,
        ref FWPM_SESSION0 session,
        out IntPtr engineHandle);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmEngineClose0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmFilterAdd0(
        IntPtr engineHandle,
        ref FWPM_FILTER0 filter,
        IntPtr securityDescriptor,
        out ulong id);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmFilterDeleteById0(IntPtr engineHandle, ulong id);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmFilterCreateEnumHandle0(
        IntPtr engineHandle,
        IntPtr enumTemplate,
        out IntPtr enumHandle);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmFilterEnum0(
        IntPtr engineHandle,
        IntPtr enumHandle,
        uint numEntriesRequested,
        out IntPtr entries,
        out uint numEntriesReturned);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engineHandle, IntPtr enumHandle);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern void FwpmFreeMemory0(ref IntPtr memory);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    internal static extern uint FwpmLayerGetByKey0(IntPtr engineHandle, ref Guid key, out IntPtr layer);

    // ------------------------------------------------------------- Strukturen

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_BYTE_BLOB
    {
        internal uint Size;
        internal IntPtr Data;
    }

    /// <summary>
    /// FWP_VALUE0. Die Union wird als <see cref="LayoutKind.Explicit"/> mit
    /// allen Varianten auf Offset 0 abgebildet, damit sie 8 Byte belegt und
    /// die 8-Byte-Ausrichtung erhalten bleibt. Es wird nur
    /// <see cref="Uint64"/> und <see cref="ByteBlobPtr"/> verwendet.
    /// </summary>
    [StructLayout(LayoutKind.Explicit)]
    internal struct FWP_VALUE0
    {
        [FieldOffset(0)]
        internal uint Type;

        [FieldOffset(8)]
        internal ulong Uint64;

        [FieldOffset(8)]
        internal IntPtr ByteBlobPtr;
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct FWP_CONDITION_VALUE0
    {
        [FieldOffset(0)]
        internal uint Type;

        [FieldOffset(8)]
        internal ulong Uint64;

        [FieldOffset(8)]
        internal IntPtr ByteBlobPtr;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWP_BYTE_ARRAY16
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        internal byte[] ByteArray16;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_FILTER_CONDITION0
    {
        internal Guid FieldKey;
        internal uint MatchType;
        internal FWP_CONDITION_VALUE0 ConditionValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_FILTER0
    {
        internal Guid FilterKey;
        internal Guid DisplayDataName;

        /// <summary>
        /// Diagnostischer Anzeigename. Liegt als Wert-Struct direkt im
        /// Filter (kein Zeiger), damit kein zusaetzlicher Speicher verwaltet
        /// werden muss.
        /// </summary>
        internal FWPM_DISPLAY_DATA0 DisplayData;

        internal uint Flags;

        internal IntPtr ProviderKey;
        internal FWP_BYTE_BLOB ProviderData;

        internal Guid LayerKey;
        internal Guid SublayerKey;

        internal ulong Weight;

        internal IntPtr RawContext;
        internal Guid ProviderContextKey;

        internal IntPtr Reserved;
        internal ulong FilterId;

        internal FWP_VALUE0 EffectiveWeight;

        internal uint NumFilterConditions;
        internal IntPtr FilterCondition;

        internal IntPtr Transaction;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_DISPLAY_DATA0
    {
        internal IntPtr Name;
        internal IntPtr Description;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FWPM_SESSION0
    {
        internal Guid SessionKey;

        internal FWPM_DISPLAY_DATA0 DisplayData;

        internal uint Flags;
        internal uint TxnWaitTimeoutInMSec;
        internal uint ProcessId;
        internal IntPtr Sid;
        internal IntPtr Username;
        internal int KernelMode;
    }
}

/// <summary>
/// Die von Cordon verwendeten WFP-Schluessel.
/// <para>
/// <b>Herkunft der GUIDs:</b> Diese Werte sind Teil der stabilen
/// WFP-ABI (<c>fwpmu.h</c> / <c>fwpmk.h</c>) und duerfen sich nicht aendern,
/// sind aber nicht in jedem Fall auf MS Learn dokumentiert. Deshalb prueft
/// <see cref="WfpEnforcement"/> sie beim Start zusaetzlich zur Laufzeit
/// ueber <c>FwpmLayerGetByKey0</c>: ein nicht aufloesbarer Layer fuehrt zu
/// einem <b>Fehler</b> und nicht zu einer stillschweigend nicht gesetzten
/// Regel.
/// </para>
/// </summary>
internal static class WfpKeys
{
    /// <summary>FWPM_LAYER_ALE_AUTH_CONNECT_V4</summary>
    internal static readonly Guid LayerAleAuthConnectV4 =
        new("c38d57d1-05a7-4c33-904f-7fbceee60e82");

    /// <summary>FWPM_LAYER_ALE_AUTH_CONNECT_V6</summary>
    internal static readonly Guid LayerAleAuthConnectV6 =
        new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");

    /// <summary>FWPM_CONDITION_ALE_PACKAGE_ID</summary>
    internal static readonly Guid ConditionAlePackageId =
        new("71bc78fa-f17c-499e-a602-ab3ab3f9d2ac");

    /// <summary>FWPM_SUBLAYER_UNIVERSAL — der universelle Sublayer.</summary>
    internal static readonly Guid SublayerUniversal =
        new("eebecc03-ced4-4380-819a-395786f70789");
}
