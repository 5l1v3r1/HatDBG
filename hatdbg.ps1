Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Collections.Generic;

[Flags]
public enum CONSTANT : uint
{
	DEBUG_PROCESS         	= 0x00000001,
	CREATE_NEW_CONSOLE    	= 0x00000010,
	PROCESS_ALL_ACCESS    	= 0x001F0FFF,
	INFINITE              	= 0xFFFFFFFF,
	DBG_CONTINUE          	= 0x00010002,
}

[Flags]
public enum DEBUG_CONSTANT : uint
{
	EXCEPTION_DEBUG_EVENT      =    0x1,
	CREATE_THREAD_DEBUG_EVENT  =    0x2,
	CREATE_PROCESS_DEBUG_EVENT =    0x3,
	EXIT_THREAD_DEBUG_EVENT    =    0x4,
	EXIT_PROCESS_DEBUG_EVENT   =    0x5,
	LOAD_DLL_DEBUG_EVENT       =    0x6,
	UNLOAD_DLL_DEBUG_EVENT     =    0x7,
	OUTPUT_DEBUG_STRING_EVENT  =    0x8,
	RIP_EVENT                  =    0x9,
}

[Flags]
public enum EXCEPTION_CONSTANT : uint
{
	EXCEPTION_ACCESS_VIOLATION     = 0xC0000005,
	EXCEPTION_BREAKPOINT           = 0x80000003,
	EXCEPTION_GUARD_PAGE           = 0x80000001,
	EXCEPTION_SINGLE_STEP          = 0x80000004,
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
    NONE					= 0,
    DEBUG_PROCESS 				= 0x00000001,
    DEBUG_ONLY_THIS_PROCESS 			= 0x00000002,
    CREATE_SUSPENDED 				= 0x00000004,
    DETACHED_PROCESS 				= 0x00000008,
    CREATE_NEW_CONSOLE 				= 0x00000010,
    CREATE_NEW_PROCESS_GROUP 			= 0x00000200,
    CREATE_UNICODE_ENVIRONMENT 			= 0x00000400,
    CREATE_SEPARATE_WOW_VDM 			= 0x00000800,
    CREATE_SHARED_WOW_VDM 			= 0x00001000,
    CREATE_PROTECTED_PROCESS 			= 0x00040000,
    EXTENDED_STARTUPINFO_PRESENT 		= 0x00080000,
    CREATE_BREAKAWAY_FROM_JOB 			= 0x01000000,
    CREATE_PRESERVE_CODE_AUTHZ_LEVEL 		= 0x02000000,
    CREATE_DEFAULT_ERROR_MODE 			= 0x04000000,
    CREATE_NO_WINDOW 				= 0x08000000,
}
[Flags]
public enum STARTF : uint
{
    STARTF_USESHOWWINDOW 		= 0x00000001,
    STARTF_USESIZE 			= 0x00000002,
    STARTF_USEPOSITION 			= 0x00000004,
    STARTF_USECOUNTCHARS 		= 0x00000008,
    STARTF_USEFILLATTRIBUTE 		= 0x00000010,
    STARTF_RUNFULLSCREEN 		= 0x00000020, 
    STARTF_FORCEONFEEDBACK 		= 0x00000040,
    STARTF_FORCEOFFFEEDBACK 		= 0x00000080,
    STARTF_USESTDHANDLES 		= 0x00000100,
}
public enum ShowWindow : short
{
    SW_HIDE 		= 0,
    SW_SHOWNORMAL 	= 1,
    SW_NORMAL 		= 1,
    SW_SHOWMINIMIZED 	= 2,
    SW_SHOWMAXIMIZED 	= 3,
    SW_MAXIMIZE 	= 3,
    SW_SHOWNOACTIVATE 	= 4,
    SW_SHOW 		= 5,
    SW_MINIMIZE 	= 6,
    SW_SHOWMINNOACTIVE 	= 7,
    SW_SHOWNA 		= 8,
    SW_RESTORE 		= 9,
    SW_SHOWDEFAULT 	= 10,
    SW_FORCEMINIMIZE 	= 11,
    SW_MAX 		= 11
}
[Flags]
public enum ProcessAccess : uint
{
	Terminate 		= 0x00000001,
	CreateThread 		= 0x00000002,
	VMOperation 		= 0x00000008,
	VMRead 			= 0x00000010,
	VMWrite 		= 0x00000020,
	DupHandle 		= 0x00000040,
	SetInformation 		= 0x00000200,
	QueryInformation 	= 0x00000400,
	SuspendResume 		= 0x00000800,
	Synchronize 		= 0x00100000,
	All 			= 0x001F0FFF
}
[Flags]
public enum ThreadAccess : int
{
	TERMINATE           	= (0x0001),
	SUSPEND_RESUME      	= (0x0002),
	GET_CONTEXT         	= (0x0008),
	SET_CONTEXT         	= (0x0010),
	SET_INFORMATION     	= (0x0020),
	QUERY_INFORMATION	= (0x0040),
	SET_THREAD_TOKEN    	= (0x0080),
	IMPERSONATE         	= (0x0100),
	DIRECT_IMPERSONATION    = (0x0200),
	THREAD_ALL_ACCESS	= 0x001F03FF,
}
  
[Flags]
public enum SnapshotFlags : uint
{
	HeapList 	= 0x00000001,
	Process 	= 0x00000002,
	Thread 		= 0x00000004,
	Module 		= 0x00000008,
	Module32 	= 0x00000010,
	Inherit 	= 0x80000000,
	All 		= 0x0000001F,
	NoHeaps 	= 0x40000000
}
[Flags]
public enum CONTEXT_FLAGS : uint
{
   CONTEXT_i386 = 0x10000,
   CONTEXT_i486 = 0x10000,   //  same as i386
   CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
   CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
   CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
   CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
   CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
   CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
   CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
   CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS |  CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS |  CONTEXT_EXTENDED_REGISTERS
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
[StructLayout(LayoutKind.Sequential)]
public struct THREADENTRY32
{
	public uint dwSize;
	public uint cntUsage;
	public uint th32ThreadID;
	public uint th32OwnerProcessID;
	public uint tpBasePri;
	public uint tpDeltaPri;
	public uint dwFlags;
}
[StructLayout(LayoutKind.Sequential)]
public struct FLOATING_SAVE_AREA
{
     public uint ControlWord;
     public uint StatusWord;
     public uint TagWord;
     public uint ErrorOffset;
     public uint ErrorSelector;
     public uint DataOffset;
     public uint DataSelector;
     [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
     public byte[] RegisterArea;
     public uint Cr0NpxState;
}
[StructLayout(LayoutKind.Sequential)]
public struct CONTEXT
{
	public uint ContextFlags;
	public uint Dr0;
	public uint Dr1;
	public uint Dr2;
	public uint Dr3;
	public uint Dr6;
	public uint Dr7;
	public FLOATING_SAVE_AREA FloatSave;
	public uint SegGs;
	public uint SegFs;
	public uint SegEs;
	public uint SegDs;
	public uint Edi;
	public uint Esi;
	public uint Ebx;
	public uint Edx;
	public uint Ecx;
	public uint Eax;
	public uint Ebp;
	public uint Eip;
	public uint SegCs;
	public uint EFlags;
	public uint Esp;
	public uint SegSs;
	[MarshalAs(UnmanagedType.ByValArray, SizeConst=0x200, ArraySubType=UnmanagedType.I1)]
	public byte[] ExtendedRegisters;
} 
	
public class DEBUGGER
{
	public IntPtr h_process;
	public IntPtr h_thread;
	public uint dwpid;
	public bool debugger_active;
	public CONTEXT context;
	public Dictionary<IntPtr, byte[]> breakpoint = new Dictionary<IntPtr, byte[]>();
	public uint exception;
	public IntPtr exception_address;
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
	        out PROCESS_INFORMATION lpProcessInformation
        );
		
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
	
	[DllImport("kernel32.dll")]
	public static extern IntPtr OpenThread(
		ThreadAccess dwDesiredAccess, 
		bool bInheritHandle,
		uint dwThreadId
	);
	
	[DllImport("kernel32.dll")]
	public static extern IntPtr CreateToolhelp32Snapshot(
		SnapshotFlags dwFlags,
		uint th32ProcessID
	);
	
	[DllImport("kernel32.dll")]
	public static extern bool Thread32First(
		IntPtr hSnapshot, 
		ref THREADENTRY32 lpte
	);
	
	[DllImport("kernel32.dll")]
	public static extern bool Thread32Next(
		IntPtr hSnapshot,
		out THREADENTRY32 lpte
	);
	
	[DllImport("kernel32.dll")]
	public static extern bool CloseHandle(
		IntPtr hObject
	);
	
	[DllImport("kernel32.dll")]
	public static extern bool GetThreadContext(
		IntPtr hThread,
		ref CONTEXT lpContext
	);
	
	[DllImport("kernel32.dll")]
	public static extern uint SuspendThread(
		IntPtr hThread
	);
 
	[DllImport("kernel32.dll")]
	public static extern int ResumeThread(
		IntPtr hThread
	);
	
	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern bool ReadProcessMemory(
		IntPtr hProcess,
		IntPtr lpBaseAddress,
		byte[] lpBuffer,
		int dwSize,
		out IntPtr lpNumberOfBytesRead
	);
	
	[DllImport("kernel32.dll",SetLastError = true)]
	public static extern bool WriteProcessMemory(
		IntPtr hProcess,
		IntPtr lpBaseAddress,
		byte[] lpBuffer,
		int nSize,
		out IntPtr lpNumberOfBytesWritten
	);
	
	[DllImport("kernel32.dll")]
	public static extern void RtlZeroMemory(
		IntPtr dst,
		int length
	);
	
	[DllImport("kernel32.dll", CharSet=CharSet.Auto)]
	public static extern IntPtr GetModuleHandle(
		string lpModuleName
	);
	
	[DllImport("kernel32", CharSet=CharSet.Ansi, ExactSpelling=true, SetLastError=true)]
	public static extern IntPtr GetProcAddress(
		IntPtr hModule,
		string procName
	);
}
"@
$debugger 	= New-Object DEBUGGER

Function open_thread
{
	[CmdletBinding()]param (
	[Parameter(Position = 1, Mandatory=$true)]
		[int]
		$thread_id
	)
	$h_thread = [Kernel32]::OpenThread("THREAD_ALL_ACCESS",$false,$thread_id)
	if($h_thread -ne $null)
	{
		return $h_thread
	} else {
		write-host "[-] Could not obtain a valid thread handle."
		return $false
	}
}

Function enumerate_threads
{
	$thread_entry 	= New-Object THREADENTRY32
	$thread_list 	= New-Object System.Collections.Generic.List[System.Object]
	$snapshot 		= [Kernel32]::CreateToolhelp32Snapshot("Thread",$debugger.dwpid)
	if($snapshot -ne $null)
	{
		$thread_entry.dwSize = [System.Runtime.InteropServices.Marshal]::SizeOf($thread_entry)
		$success = [Kernel32]::Thread32First($snapshot,[ref] $thread_entry)
		while($success)
		{
			if($thread_entry.th32OwnerProcessID -eq $debugger.dwpid)
			{
				$thread_list.Add($thread_entry.th32ThreadID)
			}
			$success = [Kernel32]::Thread32Next($snapshot,[ref] $thread_entry)
		}
		[Kernel32]::CloseHandle($snapshot)
		return $thread_list
		
	} else {
		return $false
	}
}

Function get_thread_context
{
	[CmdletBinding()]param (
	[Parameter(Position = 1, Mandatory=$true)]
		[int]
		$thread_id
	)
	
	$context = New-Object CONTEXT
	$context.ContextFlags = [CONTEXT_FLAGS]::CONTEXT_ALL
	$h_thread = open_thread -thread_id $thread_id
	[Kernel32]::SuspendThread($h_thread)
	if([Kernel32]::GetThreadContext($h_thread,[ref] $context))
	{
		[Kernel32]::ResumeThread($h_thread)
		[Kernel32]::CloseHandle($h_thread)
		return $context
	} else {
		[Kernel32]::ResumeThread($h_thread)
		return $false
	}
	
}

Function read_process_memory
{
	[CmdletBinding()]param (
	[Parameter(Position = 1, Mandatory=$true)]
		[int]
		$len,
	[Parameter(Position = 2, Mandatory=$true)]
		[IntPtr]
		$address
	)
	
	$data 		= New-Object Byte[]($len)
	$count 		= New-Object uint32

	if([Kernel32]::ReadProcessMemory($debugger.h_process,$address,$data,$len,[ref] $count))
	{	
		return $data
	} else {
		return $false
	}
}

Function write_process_memory
{
	[CmdletBinding()]param (
	[Parameter(Position = 1, Mandatory=$true)]
		[Byte[]]
		$data,
	[Parameter(Position = 2, Mandatory=$true)]
		[IntPtr]
		$address
	)
	
	$len 		= $data.Count
	$count 		= New-Object uint32
	if([Kernel32]::WriteProcessMemory($debugger.h_process,$address,$data,$len,[ref] $count))
	{	
		return $true
	} else {
		return $false
	}
}

Function bp_set
{
	[CmdletBinding()]param (
	[Parameter(Position = 1, Mandatory=$true)]
		[IntPtr]
		$address
	)
	if($debugger.breakpoint.ContainsKey($address) -eq $false)
	{
		write-host ("[*] Set Breakpoint at 0x{0,0:x}" -f $address)
		$original_byte = read_process_memory -len 1 -address $address
		if($original_byte -ne $false)
		{
			if(write_process_memory -data 0xCC -address $address)
			{
				$debugger.breakpoint.Add($address,$original_byte)
				return $true
			}
		}
	}
	return $false
}

Function bp_del
{
	[CmdletBinding()]param (
	[Parameter(Position = 1, Mandatory=$true)]
		[IntPtr]
		$address
	)
	if($debugger.breakpoint.ContainsKey($address) -eq $true)
	{
		write-host ("[*] Remove Breakpoint at 0x{0,0:x}" -f $address)
		$original_byte = $debugger.breakpoint[$address]
		if($original_byte -ne $false)
		{
			if(write_process_memory -data $original_byte -address $address)
			{
				return $true
			}
		}
		
	}
	return $false
	
}

Function func_resolve
{
	[CmdletBinding()]param (
	[Parameter(Position = 1, Mandatory=$true)]
		[string]
		$dll,
	[Parameter(Position = 2, Mandatory=$true)]
		[string]
		$func
	)
	
	$handle 	= [Kernel32]::GetModuleHandle($dll)
	$address 	= [Kernel32]::GetProcAddress($handle,$func)
	$result = [Kernel32]::CloseHandle($handle)
	
	return [IntPtr] $address
}

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

Function exception_handler_breakpoint
{
	write-host ("[+] Breakpoint Exception address: 0x{0,0:x}" -f $debugger.exception_address)
	return [CONSTANT]::DBG_CONTINUE
}

Function get_debug_event
{
	$debug_event 		= New-Object DEBUG_EVENT
	$continue_status	= [CONSTANT]::DBG_CONTINUE
	
	if([Kernel32]::WaitForDebugEvent([ref] $debug_event,[CONSTANT]::INFINITE))
	{
		$debugger.h_thread = open_thread -thread_id $debug_event.dwThreadId
		$context = New-Object CONTEXT
		$context = get_thread_context -thread_id $debugger.h_thread
		write-host "[+] Event Code: $($debug_event.dwDebugEventCode) Thread ID: $($debug_event.dwThreadId)"
		if($debug_event.dwDebugEventCode -eq [DEBUG_CONSTANT]::EXCEPTION_DEBUG_EVENT)
		{
			$debugger.exception = $debug_event.u.Exception.ExceptionRecord.ExceptionCode
			$debugger.exception_address = $debug_event.u.Exception.ExceptionRecord.ExceptionAddress
			if($debugger.exception -eq [EXCEPTION_CONSTANT]::EXCEPTION_ACCESS_VIOLATION)
			{
				write-host "Access Violation Detected."
			}
			elseif($debugger.exception -eq [EXCEPTION_CONSTANT]::EXCEPTION_BREAKPOINT)
			{
				$continue_status = exception_handler_breakpoint
			}
			elseif($debugger.exception -eq [EXCEPTION_CONSTANT]::EXCEPTION_GUARD_PAGE)
			{
				write-host "Guard Page Access Detected."
			}
			elseif($debugger.exception -eq [EXCEPTION_CONSTANT]::EXCEPTION_SINGLE_STEP)
			{
				write-host "Single Stepping."
			}
		}
		$result = [Kernel32]::ContinueDebugEvent($debug_event.dwProcessId,$debug_event.dwThreadId,$continue_status)
		
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
