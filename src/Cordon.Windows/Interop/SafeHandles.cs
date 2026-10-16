using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace Cordon.Windows.Interop;

/// <summary>
/// Generisches Kernel-Handle. Wird ueberall dort verwendet, wo das Framework
/// keinen passenden <c>SafeHandle</c> anbietet (Pipe-Handles, SID-Speicher).
/// </summary>
internal sealed class SafeNativeHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeNativeHandle()
        : base(ownsHandle: true)
    {
    }

    internal SafeNativeHandle(IntPtr existingHandle, bool ownsHandle)
        : base(ownsHandle)
    {
        SetHandle(existingHandle);
    }

    protected override bool ReleaseHandle() => NativeMethods.CloseHandle(handle);
}

/// <summary>
/// Ein Job-Object-Handle.
/// <para>
/// Eigenes Handle statt <see cref="SafeNativeHandle"/>, weil hier eine
/// Besonderheit gilt: solange dieses Handle offen ist, gelten
/// <c>KILL_ON_JOB_CLOSE</c>-Semantik und Limits. Ein versehentlich
/// dupliziertes oder zu spaet geschlossenes Handle haelt den Agenten am
/// Leben bzw. verhindert das Aufraeumen.
/// </para>
/// </summary>
internal sealed class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeJobHandle()
        : base(ownsHandle: true)
    {
    }

    protected override bool ReleaseHandle() => NativeMethods.CloseHandle(handle);
}

/// <summary>Ein Thread-Handle (nur fuer <c>ResumeThread</c> beim Spawn).</summary>
internal sealed class SafeThreadHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal SafeThreadHandle()
        : base(ownsHandle: true)
    {
    }

    internal SafeThreadHandle(IntPtr existingHandle, bool ownsHandle)
        : base(ownsHandle)
    {
        SetHandle(existingHandle);
    }

    protected override bool ReleaseHandle() => NativeMethods.CloseHandle(handle);
}
