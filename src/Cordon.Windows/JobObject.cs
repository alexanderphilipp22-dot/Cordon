using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Cordon.Core.Model;
using Cordon.Windows.Interop;

namespace Cordon.Windows;

/// <summary>
/// Ein Windows Job Object als Isolations- und Limitgrenze fuer einen Agenten
/// und <b>alle</b> von ihm erzeugten Kindprozesse.
/// <para>
/// Die wichtigste Eigenschaft ist die Vererbung: Kindprozesse treten
/// automatisch in den Job ein, sofern sie nicht ausdruecklich mit
/// <c>CREATE_BREAKAWAY_FROM_JOB</c> erzeugt werden - und das erlaubt
/// Windows nur, wenn der Job <c>JOB_OBJECT_LIMIT_BREAKAWAY_OK</c> setzt.
/// Genau dieses Flag wird hier <b>nicht</b> gesetzt.
/// </para>
/// </summary>
public sealed class JobObject : IDisposable
{
    private readonly SafeJobHandle _handle;
    private bool _disposed;

    private JobObject(SafeJobHandle handle, SandboxLimits limits)
    {
        _handle = handle;
        Limits = limits;
    }

    public SandboxLimits Limits { get; }

    public bool IsClosed => _disposed || _handle.IsClosed || _handle.IsInvalid;

    /// <summary>
    /// Erzeugt einen Job mit den uebergebenen Limits.
    /// </summary>
    /// <param name="limits">Limits. <c>null</c> verwendet die Defaults.</param>
    /// <param name="name">
    /// Optionaler Name. Ein benannter Job ist global sichtbar - fuer Agenten
    /// wird bewusst ein unbenannter Job verwendet, damit kein anderer Prozess
    /// denselben Job oeffnen und manipulieren kann.
    /// </param>
    public static JobObject Create(SandboxLimits? limits = null, string? name = null)
    {
        var effective = limits ?? new SandboxLimits();

        var handle = NativeMethods.CreateJobObjectW(IntPtr.Zero, name);
        if (handle.IsInvalid)
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "CreateJobObjectW fehlgeschlagen.");
        }

        try
        {
            ApplyLimits(handle, effective);
        }
        catch
        {
            handle.Dispose();
            throw;
        }

        return new JobObject(handle, effective);
    }

    /// <summary>
    /// Weist einen Prozess dem Job zu. <b>Muss</b> aufgerufen werden, bevor
    /// der Hauptthread des Prozesses fortgesetzt wird - sonst existiert ein
    /// Zeitfenster, in dem ein Kindprozess ausserhalb des Jobs entstehen
    /// koennte.
    /// </summary>
    public void AssignProcess(SafeProcessHandle process)
    {
        ArgumentNullException.ThrowIfNull(process);
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (!NativeMethods.AssignProcessToJobObject(_handle, process))
        {
            var error = Marshal.GetLastWin32Error();
            throw new Win32Exception(
                error,
                "AssignProcessToJobObject fehlgeschlagen. Haeufigste Ursache: der Prozess "
                + "gehoert bereits einem Job an, der keine Verschachtelung erlaubt.");
        }
    }

    /// <summary>
    /// Beendet den Job und damit alle zugehoerigen Prozesse.
    /// <para>
    /// Es gibt bewusst keine eigene <c>TerminateJobObject</c>-Methode: das
    /// Schliessen des Handles beendet dank <c>KILL_ON_JOB_CLOSE</c> bereits
    /// alle Prozesse, und ein zweiter Weg waere eine zusaetzliche
    /// Fehlerquelle.
    /// </para>
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _handle.Dispose();
    }

    private static void ApplyLimits(SafeJobHandle handle, SandboxLimits limits)
    {
        var information = new NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        var flags = 0u;

        if (limits.ActiveProcessLimit > 0)
        {
            information.BasicLimitInformation.ActiveProcessLimit = (uint)limits.ActiveProcessLimit;
            flags |= NativeMethods.JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        }

        if (limits.ProcessMemoryLimitBytes > 0)
        {
            information.ProcessMemoryLimit = checked((UIntPtr)(ulong)limits.ProcessMemoryLimitBytes);
            flags |= NativeMethods.JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        }

        if (limits.JobMemoryLimitBytes > 0)
        {
            information.JobMemoryLimit = checked((UIntPtr)(ulong)limits.JobMemoryLimitBytes);
            flags |= NativeMethods.JOB_OBJECT_LIMIT_JOB_MEMORY;
        }

        if (limits.JobCpuTimeSeconds > 0)
        {
            // 100-ns-Intervalle, negatives Vorzeichen = kumulative Job-Zeit.
            information.BasicLimitInformation.PerJobUserTimeLimit =
                -(limits.JobCpuTimeSeconds * 10_000_000L);
            flags |= NativeMethods.JOB_OBJECT_LIMIT_JOB_TIME;
        }

        // Immer gesetzt: kein Agent ueberlebt ein Cordon-Aus. Ohne dieses Flag
        // wuerde ein Agent nach einem Dienst-Neustart als Waise weiterlaufen -
        // ohne Identitaetsbindung an eine Pipe und damit ohne Policy.
        flags |= NativeMethods.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        // BREAKAWAY_OK und SILENT_BREAKAWAY_OK werden bewusst NICHT gesetzt.
        // Wuerde eines davon gesetzt, koennte ein Kindprozess mit
        // CREATE_BREAKAWAY_FROM_JOB aus der Grenze austreten.

        information.BasicLimitInformation.LimitFlags = flags;

        var size = Marshal.SizeOf<NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
        var buffer = Marshal.AllocHGlobal(size);

        try
        {
            Marshal.StructureToPtr(information, buffer, fDeleteOld: false);

            if (!NativeMethods.SetInformationJobObject(
                    handle,
                    NativeMethods.JOBOBJECTINFOCLASS.JobObjectExtendedLimitInformation,
                    buffer,
                    (uint)size))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "SetInformationJobObject(JobObjectExtendedLimitInformation) fehlgeschlagen.");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>
    /// Liest die tatsaechlich wirksamen Limits zurueck. Wird von
    /// <c>cordon doctor</c> verwendet, um zu belegen, dass die Grenze
    /// tatsaechlich gesetzt wurde, statt es nur anzunehmen.
    /// </summary>
    public uint QueryActiveProcessLimit()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var size = Marshal.SizeOf<NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
        var buffer = Marshal.AllocHGlobal(size);

        try
        {
            if (!NativeMethods.QueryInformationJobObject(
                    _handle,
                    NativeMethods.JOBOBJECTINFOCLASS.JobObjectExtendedLimitInformation,
                    buffer,
                    (uint)size,
                    out _))
            {
                throw new Win32Exception(
                    Marshal.GetLastWin32Error(),
                    "QueryInformationJobObject fehlgeschlagen.");
            }

            var information = Marshal.PtrToStructure<NativeMethods.JOBOBJECT_EXTENDED_LIMIT_INFORMATION>(buffer);
            return information.BasicLimitInformation.ActiveProcessLimit;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
