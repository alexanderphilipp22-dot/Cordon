using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Cordon.Windows.Interop;

namespace Cordon.Windows;

/// <summary>
/// Optionale zweite Verteidigungslinie: blockiert jeden ausgehenden
/// Verbindungsaufbau fuer eine AppContainer-Package-SID.
/// <para>
/// <b>Redundant zur AppContainer-Grenze - mit Absicht.</b> Der AppContainer
/// verweigert Netzwerk bereits im Token. Diese Regel faengt den Fall ab, dass
/// ein Agent versehentlich <i>mit</i> Netzwerk-Capability gestartet wird,
/// und sie gilt fuer <b>jeden</b> Prozess dieser Package-SID, auch fuer
/// einen, der nicht im Job Object ist.
/// </para>
/// <para>
/// <b>Standardmaessig dynamisch:</b> die WFP-Session traegt
/// <c>FWPM_SESSION_FLAG_DYNAMIC</c>, damit die Regel mit dem Cordon-Prozess
/// verschwindet. Ein Agent darf niemals dauerhaft netzlos auf dem Host
/// zurueckbleiben, nur weil Cordon abgestuerzt ist.
/// </para>
/// </summary>
public sealed class WfpEnforcement : IDisposable
{
    private readonly IntPtr _engineHandle;
    private readonly List<ulong> _filterIds = [];
    private readonly bool _persistent;
    private bool _disposed;

    private WfpEnforcement(IntPtr engineHandle, bool persistent)
    {
        _engineHandle = engineHandle;
        _persistent = persistent;
    }

    /// <summary>Anzahl der gesetzten Filter.</summary>
    public int FilterCount => _filterIds.Count;

    public bool IsPersistent => _persistent;

    public IReadOnlyList<ulong> FilterIds => _filterIds;

    /// <summary>
    /// Oeffnet eine WFP-Session und legt die Blockierfilter fuer eine
    /// Package-SID an.
    /// </summary>
    /// <param name="packageSid">Package-SID des Agenten.</param>
    /// <param name="persistent">
    /// <c>true</c> nur auf ausdruecklichen Wunsch. Persistente Filter
    /// ueberleben einen Neustart und muessen manuell entfernt werden.
    /// </param>
    public static WfpEnforcement ApplyTo(SecurityIdentifier packageSid, bool persistent = false)
    {
        ArgumentNullException.ThrowIfNull(packageSid);

        if (!Environment.Is64BitProcess)
        {
            // Die Struct-Layouts sind auf x64 ausgelegt. Auf x86 waeren
            // UIntPtr-Felder 4 Byte breit; das wuerde hier stillschweigend
            // falsche Speicherlayouts ergeben.
            throw new PlatformNotSupportedException(
                "Die WFP-Anbindung ist fuer x64 ausgelegt. Auf x86 muessten die "
                + "Struct-Layouts angepasst werden.");
        }

        var engineHandle = OpenEngine(persistent);
        var enforcement = new WfpEnforcement(engineHandle, persistent);

        try
        {
            enforcement.VerifyLayers();
            enforcement.AddBlockFilter(WfpKeys.LayerAleAuthConnectV4, packageSid);
            enforcement.AddBlockFilter(WfpKeys.LayerAleAuthConnectV6, packageSid);
            return enforcement;
        }
        catch
        {
            enforcement.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        if (_engineHandle == IntPtr.Zero)
        {
            return;
        }

        if (!_persistent)
        {
            // Dynamische Filter verschwinden mit der Session. Explizites
            // Loeschen ist trotzdem sinnvoll, damit die Session sofort
            // aufgeraeumt werden kann.
            foreach (var filterId in _filterIds)
            {
                _ = WfpNative.FwpmFilterDeleteById0(_engineHandle, filterId);
            }
        }

        _filterIds.Clear();
        _ = WfpNative.FwpmEngineClose0(_engineHandle);
    }

    private static IntPtr OpenEngine(bool persistent)
    {
        var session = new WfpNative.FWPM_SESSION0
        {
            ProcessId = (uint)Environment.ProcessId,
            Flags = persistent
                ? 0u
                : WfpNative.FWPM_SESSION_FLAG_DYNAMIC,
        };

        var result = WfpNative.FwpmEngineOpen0(
            null,
            // RPC_C_AUTHN_WINNT
            10,
            IntPtr.Zero,
            ref session,
            out var engineHandle);

        if (result != WfpNative.FWP_E_SUCCESS || engineHandle == IntPtr.Zero)
        {
            throw new Win32Exception(
                unchecked((int)result),
                "FwpmEngineOpen0 fehlgeschlagen. WFP-Regeln benoetigen Administratorrechte. "
                + $"HRESULT=0x{result:X8}");
        }

        return engineHandle;
    }

    /// <summary>
    /// Prueft, dass die verwendeten Layer-Schluessel in dieser
    /// Windows-Version existieren. Ein falscher Schluessel wuerde sonst zu
    /// einem Filter fuehren, der nie greift - und das waere schlimmer als
    /// ein Fehler, weil es unbemerkt bliebe.
    /// </summary>
    private void VerifyLayers()
    {
        VerifyLayer(WfpKeys.LayerAleAuthConnectV4, nameof(WfpKeys.LayerAleAuthConnectV4));
        VerifyLayer(WfpKeys.LayerAleAuthConnectV6, nameof(WfpKeys.LayerAleAuthConnectV6));
    }

    private void VerifyLayer(Guid layerKey, string name)
    {
        var key = layerKey;
        var result = WfpNative.FwpmLayerGetByKey0(_engineHandle, ref key, out var layer);

        if (result != WfpNative.FWP_E_SUCCESS)
        {
            throw new InvalidOperationException(
                $"WFP-Layer '{name}' ({layerKey}) ist auf diesem System nicht aufloesbar. "
                + $"HRESULT=0x{result:X8}. Die Regel wird nicht gesetzt - fail closed.");
        }

        if (layer != IntPtr.Zero)
        {
            var memory = layer;
            WfpNative.FwpmFreeMemory0(ref memory);
        }
    }

    private void AddBlockFilter(Guid layerKey, SecurityIdentifier packageSid)
    {
        var sidBytes = new byte[packageSid.BinaryLength];
        packageSid.GetBinaryForm(sidBytes, 0);

        var sidPointer = Marshal.AllocHGlobal(sidBytes.Length);
        var conditionPointer = IntPtr.Zero;

        try
        {
            Marshal.Copy(sidBytes, 0, sidPointer, sidBytes.Length);

            var blob = new WfpNative.FWP_BYTE_BLOB
            {
                Size = (uint)sidBytes.Length,
                Data = sidPointer,
            };

            var blobSize = Marshal.SizeOf<WfpNative.FWP_BYTE_BLOB>();
            var blobPointer = Marshal.AllocHGlobal(blobSize);
            var conditionSize = Marshal.SizeOf<WfpNative.FWPM_FILTER_CONDITION0>();
            var displayNamePointer = Marshal.StringToHGlobalUni("Cordon: AppContainer Outbound Block");
            var displayDescriptionPointer = Marshal.StringToHGlobalUni(
                "Von Cordon gesetzte Default-Deny-Regel fuer eine Agent-Package-SID.");

            try
            {
                Marshal.StructureToPtr(blob, blobPointer, fDeleteOld: false);

                var condition = new WfpNative.FWPM_FILTER_CONDITION0
                {
                    FieldKey = WfpKeys.ConditionAlePackageId,
                    MatchType = WfpNative.FWP_MATCH_EQUAL,
                    ConditionValue = new WfpNative.FWP_CONDITION_VALUE0
                    {
                        Type = WfpNative.FWP_BYTE_BLOB_TYPE,
                        ByteBlobPtr = blobPointer,
                    },
                };

                conditionPointer = Marshal.AllocHGlobal(conditionSize);
                Marshal.StructureToPtr(condition, conditionPointer, fDeleteOld: false);

                var filter = new WfpNative.FWPM_FILTER0
                {
                    DisplayDataName = Guid.NewGuid(),
                    DisplayData = new WfpNative.FWPM_DISPLAY_DATA0
                    {
                        Name = displayNamePointer,
                        Description = displayDescriptionPointer,
                    },
                    Flags = _persistent ? WfpNative.FWPM_FILTER_FLAG_PERSISTENT : 0u,
                    LayerKey = layerKey,

                    // Der universelle Sublayer ist immer vorhanden und hat
                    // ein hohes Gewicht, sodass unsere Regel nicht von
                    // anderen Sublayern ueberstimmt wird.
                    SublayerKey = WfpKeys.SublayerUniversal,
                    Weight = WfpNative.BlockWeight,
                    NumFilterConditions = 1,
                    FilterCondition = conditionPointer,
                    EffectiveWeight = new WfpNative.FWP_VALUE0
                    {
                        Type = WfpNative.FWP_EMPTY,
                    },
                };

                var result = WfpNative.FwpmFilterAdd0(
                    _engineHandle,
                    ref filter,
                    IntPtr.Zero,
                    out var filterId);

                if (result != WfpNative.FWP_E_SUCCESS)
                {
                    throw new Win32Exception(
                        unchecked((int)result),
                        $"FwpmFilterAdd0 fuer Layer {layerKey} fehlgeschlagen. HRESULT=0x{result:X8}");
                }

                _filterIds.Add(filterId);
            }
            finally
            {
                if (conditionPointer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(conditionPointer);
                }

                Marshal.FreeHGlobal(blobPointer);
                Marshal.FreeHGlobal(displayNamePointer);
                Marshal.FreeHGlobal(displayDescriptionPointer);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(sidPointer);
        }
    }
}
