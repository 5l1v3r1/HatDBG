Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;


[Flags]
public enum CONSTANT : uint
{
	DEBUG_PROCESS         = 0x00000001,
	CREATE_NEW_CONSOLE    = 0x00000010,
	PROCESS_ALL_ACCESS    = 0x001F0FFF,
	INFINITE              = 0xFFFFFFFF,
	DBG_CONTINUE          = 0x00010002,
}

[StructLayout(LayoutKind.Sequential)]
public struct PROCESS_INFORMATION
{
    public IntPtr hProcess;
    public IntPtr hThread;
    public uint dwProcessId;
    public uint dwThreadId;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct STARTUPINFO
{
    public uint cb;
    public string lpReserved;
    public string lpDesktop;
    public string lpTitle;
    public uint dwX;
    public uint dwY;
    public uint dwXSize;
    public uint dwYSize;
    public uint dwXCountChars;
    public uint dwYCountChars;
    public uint dwFillAttribute;
    public STARTF dwFlags;
    public ShowWindow wShowWindow;
    public short cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
}

[StructLayout(LayoutKind.Sequential)]
public struct SECURITY_ATTRIBUTES
{
    public int length;
    public IntPtr lpSecurityDescriptor;
    public bool bInheritHandle;
}

[Flags]
public enum CreationFlags : int
{
    NONE = 0,
    DEBUG_PROCESS = 0x00000001,
    DEBUG_ONLY_THIS_PROCESS = 0x00000002,
    CREATE_SUSPENDED = 0x00000004,
    DETACHED_PROCESS = 0x00000008,
    CREATE_NEW_CONSOLE = 0x00000010,
    CREATE_NEW_PROCESS_GROUP = 0x00000200,
    CREATE_UNICODE_ENVIRONMENT = 0x00000400,
    CREATE_SEPARATE_WOW_VDM = 0x00000800,
    CREATE_SHARED_WOW_VDM = 0x00001000,
    CREATE_PROTECTED_PROCESS = 0x00040000,
    EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
    CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
    CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
    CREATE_DEFAULT_ERROR_MODE = 0x04000000,
    CREATE_NO_WINDOW = 0x08000000,
}

[Flags]
public enum STARTF : uint
{
    STARTF_USESHOWWINDOW = 0x00000001,
    STARTF_USESIZE = 0x00000002,
    STARTF_USEPOSITION = 0x00000004,
    STARTF_USECOUNTCHARS = 0x00000008,
    STARTF_USEFILLATTRIBUTE = 0x00000010,
    STARTF_RUNFULLSCREEN = 0x00000020, 
    STARTF_FORCEONFEEDBACK = 0x00000040,
    STARTF_FORCEOFFFEEDBACK = 0x00000080,
    STARTF_USESTDHANDLES = 0x00000100,
}

public enum ShowWindow : short
{
    SW_HIDE = 0,
    SW_SHOWNORMAL = 1,
    SW_NORMAL = 1,
    SW_SHOWMINIMIZED = 2,
    SW_SHOWMAXIMIZED = 3,
    SW_MAXIMIZE = 3,
    SW_SHOWNOACTIVATE = 4,
    SW_SHOW = 5,
    SW_MINIMIZE = 6,
    SW_SHOWMINNOACTIVE = 7,
    SW_SHOWNA = 8,
    SW_RESTORE = 9,
    SW_SHOWDEFAULT = 10,
    SW_FORCEMINIMIZE = 11,
    SW_MAX = 11
}

[Flags]
public enum ProcessAccess : uint
{
	Terminate = 0x00000001,
	CreateThread = 0x00000002,
	VMOperation = 0x00000008,
	VMRead = 0x00000010,
	VMWrite = 0x00000020,
	DupHandle = 0x00000040,
	SetInformation = 0x00000200,
	QueryInformation = 0x00000400,
	SuspendResume = 0x00000800,
	Synchronize = 0x00100000,
	All = 0x001F0FFF
}

[StructLayout(LayoutKind.Sequential)]
public struct DEBUG_EVENT
{
	public int dwDebugEventCode;
	public int dwProcessId;
	public int dwThreadId;
	public DEBUG_EVENT_UNION u;
}

[StructLayout(LayoutKind.Sequential)]
public struct EXCEPTION_DEBUG_INFO
{
	public EXCEPTION_RECORD ExceptionRecord;
	public uint dwFirstChance;
}

[StructLayout(LayoutKind.Explicit)]
public struct DEBUG_EVENT_UNION
{
	[FieldOffset(0)]
	public EXCEPTION_DEBUG_INFO Exception;
}

[StructLayout(LayoutKind.Sequential)]
public struct EXCEPTION_RECORD
{
	public uint ExceptionCode;
	public uint ExceptionFlags;
	public IntPtr ExceptionRecord;
	public IntPtr ExceptionAddress;
	public uint NumberParameters;
	[MarshalAs(UnmanagedType.ByValArray, SizeConst = 15, ArraySubType = UnmanagedType.U4)]
	public uint[] ExceptionInformation;
}
	
public class DEBUGGER
{
	public IntPtr h_process;
	public uint dwpid;
	public bool debugger_active;
}
public static class Kernel32
{
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CreateProcessA(
        string lpApplicationName, 
        string lpCommandLine, 
        ref SECURITY_ATTRIBUTES lpProcessAttributes, 
        ref SECURITY_ATTRIBUTES lpThreadAttributes,
        bool bInheritHandles, 
        CreationFlags dwCreationFlags, 
        IntPtr lpEnvironment,
        string lpCurrentDirectory, 
        ref STARTUPINFO lpStartupInfo, 
        out PROCESS_INFORMATION lpProcessInformation);
		
	[DllImport("kernel32.dll")]
    public static extern uint GetLastError();

	[DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(
		ProcessAccess dwDesiredAccess,
		bool bInheritHandle,
		uint dwProcessId
	);
	
	[DllImport("kernel32.dll")]
    public static extern bool DebugActiveProcess(
		uint dwProcessId
	);

	[DllImport("kernel32.dll")]
    public static extern bool WaitForDebugEvent(
		ref DEBUG_EVENT lpDebugEvent,
		uint dwMilliseconds
	);	
	
	[DllImport("kernel32.dll")]
    public static extern bool ContinueDebugEvent(
		uint dwProcessId,
		uint dwThreadId,
		uint dwContinueStatus
	);		

	[DllImport("kernel32.dll")]
    public static extern bool DebugActiveProcessStop(
		uint dwProcessId
	);	
	
}


"@
$debugger 	= New-Object DEBUGGER

Function detach
{
	if([Kernel32]::DebugActiveProcessStop($debugger.dwpid))
	{
		write-host "[*] Finished debugging."
		return $true
	} else {
		write-host "[-] There was an error"
		return $false
	}

}
Function get_debug_event
{
	$debug_event 		= New-Object DEBUG_EVENT
	$continue_status	= [CONSTANT]::DBG_CONTINUE
	
	if([Kernel32]::WaitForDebugEvent([ref] $debug_event,[CONSTANT]::INFINITE))
	{
		$debugger.debugger_active = $false
		[Kernel32]::ContinueDebugEvent($debug_event.dwProcessId,$debug_event.dwThreadId,$continue_status)
		
	}
}

Function run
{
	while($debugger.debugger_active)
	{
		get_debug_event
	}
}

Function open_process
{
	[CmdletBinding()]param (
	[Parameter(Position = 1, Mandatory=$true)]
		[int]
		$dwpid
	)
	$h_process 	= [Kernel32]::OpenProcess("All",$false,$dwpid)
	return $h_process
}

Function attach
{
	[CmdletBinding()]param (
	[Parameter(Position = 1, Mandatory=$true)]
		[int]
		$dwpid
	)
	$debugger.h_process = open_process -dwpid $dwpid
	if([Kernel32]::DebugActiveProcess($dwpid))
	{
		write-host "[*] Debugger Attached to PID" $dwpid
		$debugger.dwpid 			= $dwpid
		$debugger.debugger_active 	= $true
		run
	} else {
		write-host "[-] Unable to attach to the Process"
	}
}
Function load
{
	[CmdletBinding()]param (
	[Parameter(Position = 1, Mandatory=$true)]
		[string]
		$path
	)
	# dwCreation flag determines how to create the process
	$creation_flags 		= [CreationFlags]::DEBUG_PROCESS.value__
	
	# instantiate the structs
	$startupinfo 			= New-Object STARTUPINFO
	$processinformation		= New-Object PROCESS_INFORMATION
	
	# Initialize STARTUPINFO struct
	$startupinfo.dwFlags  		= "STARTF_USESHOWWINDOW"
	$startupinfo.wShowWindow 	= "SW_HIDE"
	$startupinfo.cb 			= [System.Runtime.InteropServices.Marshal]::SizeOf($startupinfo)
	
	# Initialize SECURITY_ATTRIBUTES struct
	$pSec = New-Object SECURITY_ATTRIBUTES
	$tSec = New-Object SECURITY_ATTRIBUTES
	$pSec.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($pSec)
	$tSec.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($tSec)
	
	$CreateProcessAResult 	= [Kernel32]::CreateProcessA($path, $null, [ref] $pSec, [ref] $tSec, $false, "DEBUG_PROCESS", [IntPtr]::Zero, ($path -split ":")[0]+":", [ref] $startupinfo, [ref] $processinformation)
	if($CreateProcessAResult)
	{
		write-host "[*] We have successfully launched process."
		write-host "[*] PID: " $processinformation.dwProcessId
		$debugger.h_process = open_process -dwpid $processinformation.dwProcessId
	} else {
		write-host "[-] Error"
		[Kernel32]::GetLastError()
	}	


}
