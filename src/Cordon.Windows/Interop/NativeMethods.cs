using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Cordon.Windows.Interop;

/// <summary>
/// Alle P/Invoke-Deklarationen an einer Stelle.
/// <para>
/// <b>Handle-Disziplin:</b> Jedes Kernel-Handle wird in einem
/// <c>SafeHandle</c> gehalten. Bei Job Objects ist das nicht Kosmetik: ein
/// geleaktes Job-Handle mit <c>KILL_ON_JOB_CLOSE</c> haelt den Agenten
/// kuenstlich am Leben.
/// </para>
/// </summary>
internal static class NativeMethods
{
    internal const uint ERROR_SUCCESS = 0;

    internal const int ERROR_ALREADY_EXISTS = 183;

    internal const int HRESULT_ALREADY_EXISTS = unchecked((int)0x800700B7);

    internal const int ERROR_INSUFFICIENT_BUFFER = 122;

    internal const uint GENERIC_READ = 0x80000000;

    internal const uint GENERIC_WRITE = 0x40000000;

    internal const uint GENERIC_ALL = 0x10000000;

    internal const uint SYNCHRONIZE = 0x00100000;

    internal const uint READ_CONTROL = 0x00020000;

    internal const uint WRITE_DAC = 0x00040000;

    internal const uint FILE_SHARE_READ = 0x00000001;

    internal const uint FILE_SHARE_WRITE = 0x00000002;

    internal const uint FILE_SHARE_DELETE = 0x00000004;

    internal const uint OPEN_EXISTING = 3;

    // Rechte, die ein Agent auf der Pipe braucht. Bewusst NICHT FILE_ALL_ACCESS
    // und bewusst ohne WRITE_DAC - der Agent darf die ACL nicht aendern.
    internal const uint NamedPipeAgentAccess =
        GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE | READ_CONTROL;

    // ---------------------------------------------------------------- Pipes

    // Hinweis: Die Signatur nimmt bewusst den Basis-Typ `SafeHandle` statt
    // `SafeNativeHandle` an. Der P/Invoke-Marshaller pinnt das Handle waehrend
    // des Aufrufs (AddRef/Release) und verhindert so Handle-Recycling zwischen
    // `DangerousGetHandle()` und dem eigentlichen Kernel-Aufruf.
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetNamedPipeClientProcessId(
        SafeHandle pipe,
        out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetNamedPipeServerProcessId(
        SafeHandle pipe,
        out uint serverProcessId);

    // -------------------------------------------------------------- Handles

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr handle);

    // ------------------------------------------------- Prozess-Zeitstempel

    /// <summary>
    /// Liest Erzeugungs- und Exitzeiten eines Prozesses. Wird fuer die
    /// PID-Reuse-Erkennung benoetigt: die Erzeugungszeit ist der einzige
    /// guenstig abfragbare Wert, der eine Prozess-<i>instanz</i> von einer
    /// spaeter unter derselben PID laufenden Instanz unterscheidet.
    /// </summary>
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetProcessTimes(
        SafeProcessHandle process,
        out long creationTime,
        out long exitTime,
        out long kernelTime,
        out long userTime);

    // ------------------------------------------------------------- Prozesse

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern SafeProcessHandle OpenProcess(
        uint desiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandle,
        uint processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryFullProcessImageNameW(
        SafeProcessHandle process,
        uint flags,
        [Out] char[] exeName,
        ref uint size);

    // ---------------------------------------------------------------- Token

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool OpenProcessToken(
        SafeProcessHandle processHandle,
        uint desiredAccess,
        out SafeAccessTokenHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetTokenInformation(
        SafeAccessTokenHandle tokenHandle,
        int tokenInformationClass,
        IntPtr tokenInformation,
        uint tokenInformationLength,
        out uint returnLength);

    // ------------------------------------------------------------- Job Object

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern SafeJobHandle CreateJobObjectW(
        IntPtr jobAttributes,
        string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetInformationJobObject(
        SafeJobHandle job,
        JOBOBJECTINFOCLASS informationClass,
        IntPtr jobObjectInformation,
        uint jobObjectInformationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryInformationJobObject(
        SafeJobHandle job,
        JOBOBJECTINFOCLASS informationClass,
        IntPtr jobObjectInformation,
        uint jobObjectInformationLength,
        out uint returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool AssignProcessToJobObject(
        SafeJobHandle job,
        SafeProcessHandle process);

    // ------------------------------------------------------- Prozess erzeugen

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateProcessW(
        string? applicationName,
        IntPtr commandLine,
        IntPtr processAttributes,
        IntPtr threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles,
        uint creationFlags,
        IntPtr environment,
        string? currentDirectory,
        ref STARTUPINFOEXW startupInfo,
        out PROCESS_INFORMATION processInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool InitializeProcThreadAttributeList(
        IntPtr attributeList,
        uint attributeCount,
        uint flags,
        ref IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool UpdateProcThreadAttribute(
        IntPtr attributeList,
        uint flags,
        IntPtr attribute,
        IntPtr value,
        IntPtr size,
        IntPtr previousValue,
        IntPtr returnSize);

    [DllImport("kernel32.dll")]
    internal static extern void DeleteProcThreadAttributeList(IntPtr attributeList);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint ResumeThread(SafeThreadHandle thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);

    // ------------------------------------------------------------ AppContainer

    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern int CreateAppContainerProfile(
        string appContainerName,
        string displayName,
        string description,
        IntPtr capabilities,
        uint capabilityCount,
        out IntPtr appContainerSid);

    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern int DeleteAppContainerProfile(string appContainerName);

    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern int DeriveAppContainerSidFromAppContainerName(
        string appContainerName,
        out IntPtr appContainerSid);

    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern int DeriveCapabilitySidsFromCapabilityName(
        string capabilityName,
        out IntPtr capabilityGroupSids,
        out uint capabilityGroupSidCount,
        out IntPtr capabilitySids,
        out uint capabilitySidCount);

    // --------------------------------------------------------------- Netzwerk

    [DllImport("userenv.dll", SetLastError = true)]
    internal static extern int NetworkIsolationSetAppContainerConfig(
        uint appContainerCount,
        [In] SID_AND_ATTRIBUTES[] appContainers);

    [DllImport("userenv.dll", SetLastError = true)]
    internal static extern int NetworkIsolationGetAppContainerConfig(
        out uint appContainerCount,
        out IntPtr appContainers);

    // ------------------------------------------------------------------- SID

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr stringSid);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool ConvertStringSidToSidW(string stringSid, out IntPtr sid);

    [DllImport("advapi32.dll")]
    internal static extern IntPtr GetSidSubAuthority(IntPtr sid, uint subAuthorityIndex);

    [DllImport("advapi32.dll")]
    internal static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern uint GetLengthSid(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool IsValidSid(IntPtr sid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CopySid(uint destinationLength, IntPtr destination, IntPtr source);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern IntPtr FreeSid(IntPtr sid);

    // ---------------------------------------------------------------- Dateien

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    // ------------------------------------------------------------ LocalFree

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr LocalFree(IntPtr handle);

    // ------------------------------------------------------------ Strukturen

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_AND_ATTRIBUTES
    {
        internal IntPtr Sid;
        internal uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_MANDATORY_LABEL
    {
        internal SID_AND_ATTRIBUTES Label;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_CAPABILITIES
    {
        internal IntPtr AppContainerSid;
        internal IntPtr Capabilities;
        internal uint CapabilityCount;
        internal uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct STARTUPINFO
    {
        internal uint cb;
        internal IntPtr lpReserved;
        internal IntPtr lpDesktop;
        internal IntPtr lpTitle;
        internal uint dwX;
        internal uint dwY;
        internal uint dwXSize;
        internal uint dwYSize;
        internal uint dwXCountChars;
        internal uint dwYCountChars;
        internal uint dwFillAttribute;
        internal uint dwFlags;
        internal ushort wShowWindow;
        internal ushort cbReserved2;
        internal IntPtr lpReserved2;
        internal IntPtr hStdInput;
        internal IntPtr hStdOutput;
        internal IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct STARTUPINFOEXW
    {
        internal STARTUPINFO StartupInfo;
        internal IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        internal IntPtr hProcess;
        internal IntPtr hThread;
        internal uint dwProcessId;
        internal uint dwThreadId;
    }

    /// <summary>
    /// JOBOBJECT_BASIC_LIMIT_INFORMATION. Die Bitmaske fuer
    /// <c>LimitFlags</c> ist 32 Bit breit, die Felder danach sind 64 Bit.
    /// Ohne <c>Pack</c> ergibt sich durch Alignment dennoch das korrekte
    /// Layout (4+4+8+4+4+4+4 = 32, danach 8-Byte-Felder).
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        internal long PerProcessUserTimeLimit;
        internal long PerJobUserTimeLimit;
        internal uint LimitFlags;
        internal UIntPtr MinimumWorkingSetSize;
        internal UIntPtr MaximumWorkingSetSize;
        internal uint ActiveProcessLimit;
        internal UIntPtr Affinity;
        internal uint PriorityClass;
        internal uint SchedulingClass;
    }

    /// <summary>
    /// IO_COUNTERS. Alle Felder sind <c>ULONGLONG</c> und damit 8-Byte
    /// ausgerichtet - das Struct ist 48 Byte gross und hat kein Padding.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct IO_COUNTERS
    {
        internal ulong ReadOperationCount;
        internal ulong WriteOperationCount;
        internal ulong OtherOperationCount;
        internal ulong ReadTransferCount;
        internal ulong WriteTransferCount;
        internal ulong OtherTransferCount;
    }

    /// <summary>
    /// JOBOBJECT_EXTENDED_LIMIT_INFORMATION. Die Reihenfolge der Felder
    /// entspricht der Windows-Definition: BasicLimitInformation, dann
    /// IO_COUNTERS (6 x 8 Byte), dann die vier UIntPtr-Felder.
    /// <b>Alle Felder sind noetig</b> - ein zu kurzes Struct fuehrt bei
    /// SetInformationJobObject zu ERROR_BAD_LENGTH und damit zu einer
    /// stillschweigend nicht gesetzten Grenze.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        internal JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        internal IO_COUNTERS IoInfo;
        internal UIntPtr ProcessMemoryLimit;
        internal UIntPtr JobMemoryLimit;
        internal UIntPtr PeakProcessMemoryUsed;
        internal UIntPtr PeakJobMemoryUsed;
    }

    // -------------------------------------------------------------- Konstanten

    internal const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    internal const uint PROCESS_TERMINATE = 0x0001;

    internal const uint PROCESS_SET_QUOTA = 0x0100;

    internal const uint TOKEN_QUERY = 0x0008;

    internal const uint TOKEN_DUPLICATE = 0x0002;

    internal const int TokenUser = 1;

    internal const int TokenIntegrityLevel = 25;

    internal const int TokenIsAppContainer = 29;

    internal const int TokenCapabilities = 30;

    internal const int TokenAppContainerSid = 31;

    internal const uint SE_GROUP_INTEGRITY = 0x00000020;

    internal const uint SE_GROUP_INTEGRITY_ENABLED = 0x00000040;

    /// <summary>SECURITY_MANDATORY_LOW_RID.</summary>
    internal const int SECURITY_MANDATORY_LOW_RID = 0x1000;

    internal const int SECURITY_MANDATORY_MEDIUM_RID = 0x2000;

    internal const int SECURITY_MANDATORY_HIGH_RID = 0x3000;

    internal const int SECURITY_MANDATORY_SYSTEM_RID = 0x4000;

    internal const int SECURITY_MANDATORY_UNTRUSTED_RID = 0x0000;

    internal const uint CREATE_SUSPENDED = 0x00000004;

    internal const uint CREATE_NEW_CONSOLE = 0x00000010;

    internal const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;

    internal const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;

    /// <summary>PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES.</summary>
    internal static readonly IntPtr ProcThreadAttributeSecurityCapabilities = 0x20009;

    internal const uint WAIT_OBJECT_0 = 0x00000000;

    internal const uint WAIT_TIMEOUT = 0x00000102;

    internal const uint INFINITE = 0xFFFFFFFF;

    // Job Object Flags
    internal const uint JOB_OBJECT_LIMIT_WORKINGSET = 0x00000001;

    internal const uint JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002;

    internal const uint JOB_OBJECT_LIMIT_JOB_TIME = 0x00000004;

    internal const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;

    internal const uint JOB_OBJECT_LIMIT_AFFINITY = 0x00000010;

    internal const uint JOB_OBJECT_LIMIT_PRIORITY_CLASS = 0x00000020;

    internal const uint JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100;

    internal const uint JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200;

    internal const uint JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800;

    internal const uint JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000;

    internal const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;

    internal enum JOBOBJECTINFOCLASS
    {
        JobObjectBasicAccountingInformation = 1,
        JobObjectBasicLimitInformation = 2,
        JobObjectBasicProcessIdList = 3,
        JobObjectExtendedLimitInformation = 9,
    }
}
