# HatDBG
The HatDBG is A pure Powershell win32 debugging abstraction class. The goal of this project is to make a powershell debugger. It is intended to be used during internal penetration tests and red team engagements. This is exclusively for educational purposes.

The debugger objects implementing a number of features such as: 
 + Soft (INT 3) breakpoints
 + Exception / event handling call backs
 + Process memory snapshotting
 + Function resolution
 + Memory manipulation
 + Threads enumerations

## Method Summary
### open_thread
```
open_thread(thread_id)
Convenience wrapper around OpenThread().
```

### enumerate_threads
```
 enumerate_threads()
Using the CreateToolhelp32Snapshot() API enumerate all system threads returning a list of thread IDs that belong to the debuggee.
```

### get_thread_context
```
get_thread_context(thread_id)
Convenience wrapper around GetThreadContext().
```

### read_process_memory
```
read_process_memory(address, len)
Read from the debuggee process space.
```

### write_process_memory
```
write_process_memory(address, data, len)
Write to the debuggee process space.
```

### bp_set
```
bp_set(address)
Sets a breakpoint at the designated address.
```

### func_resolve
```
func_resolve(dll, func)
Utility function that resolves the address of a given module / function name pair under the context of the debugger. 
```

### detach
```
detach()
Detach from debuggee.
```

### attach
```
attach(dwpid)
Attach to the specified process by PID.
```

### exception_handler_breakpoint
```
exception_handler_breakpoint()
This is the default EXCEPTION_BREAKPOINT handler, responsible for transparently restoring soft breakpoints and passing control to the registered user callback handler. 
```

### get_debug_event
```
get_debug_event()
Geth debugger event and responsible for callback handler.
```

### run
```
run()
Enter the infinite debug event handling loop.
```

### open_process
```
open_process(dwpid)
Convenience wrapper around OpenProcess().
```

### load
```
load(path)
Load the specified executable and optional command line arguments into the debugger.
```

## Example
### Enumerate Threads
```
#Use PID for attach debugger
$result = attach -dwpid 5920
if([bool] $result)
{
$list = enumerate_threads
foreach ($thread in $list){
	$thread_context = get_thread_context -thread_id $thread
	write-host ("[+] Dumping register for thread ID: 0x{0,0:x}" -f $thread)
	write-host ("[+] EIP: 0x{0,0:x}" -f $thread_context.Eip)
	write-host ("[+] ESP: 0x{0,0:x}" -f $thread_context.Esp)
	write-host ("[+] EBP: 0x{0,0:x}" -f $thread_context.Ebp)
	write-host ("[+] EAX: 0x{0,0:x}" -f $thread_context.Eax)
	write-host ("[+] EBX: 0x{0,0:x}" -f $thread_context.Ebx)
	write-host ("[+] ECX: 0x{0,0:x}" -f $thread_context.Ecx)
	write-host ("[+] EDX: 0x{0,0:x}" -f $thread_context.Edx)
	write-host "[+] END DUMP"
}
$result = detach
}
```
Output
```
[*] Debugger Attached to PID 5920
[+] Dumping register for thread ID: 0xb14
[+] EIP: 0x75ca4d9c
[+] ESP: 0x53f610
[+] EBP: 0x53f628
[+] EAX: 0x4d3
[+] EBX: 0x0
[+] ECX: 0x0
[+] EDX: 0x0
[+] END DUMP
[+] Dumping register for thread ID: 0x1834
[+] EIP: 0x77e08c0c
[+] ESP: 0x31dfb70
[+] EBP: 0x31dfbe0
[+] EAX: 0xf5a280
[+] EBX: 0x2be8c7c
[+] ECX: 0x0
[+] EDX: 0x0
[+] END DUMP
[+] Dumping register for thread ID: 0x1770
[+] EIP: 0x77e0919c
[+] ESP: 0x32df5a8
[+] EBP: 0x32df738
[+] EAX: 0x0
[+] EBX: 0x0
[+] ECX: 0x0
[+] EDX: 0x0
[+] END DUMP
[+] Dumping register for thread ID: 0x1784
[+] EIP: 0x77e08c0c
[+] ESP: 0x4defc14
[+] EBP: 0x4defc84
[+] EAX: 0xf5a280
[+] EBX: 0x3e8
[+] ECX: 0x0
[+] EDX: 0x0
[+] END DUMP
[+] Dumping register for thread ID: 0x133c
[+] EIP: 0x77e0919c
[+] ESP: 0x500f7f0
[+] EBP: 0x500f980
[+] EAX: 0x103
[+] EBX: 0x0
[+] ECX: 0x0
[+] EDX: 0x0
[+] END DUMP
[+] Dumping register for thread ID: 0x1718
[+] EIP: 0x77e08c0c
[+] ESP: 0x778fb9c
[+] EBP: 0x778fc0c
[+] EAX: 0x0
[+] EBX: 0xcc0008
[+] ECX: 0x0
[+] EDX: 0x0
[+] END DUMP
[+] Dumping register for thread ID: 0x23b8
[+] EIP: 0x77e0aef0
[+] ESP: 0x2dcf850
[+] EBP: 0x0
[+] EAX: 0x77e41300
[+] EBX: 0x0
[+] ECX: 0x0
[+] EDX: 0x0
[+] END DUMP
[*] Finished debugging.
```

### Get Debug Event Code
```
$dwpid = Read-Host "Enter the PID of the Process to attach to"
attach -dwpid $dwpid
run
detach
```

Output
```
Enter the PID of the Process to attach to: : 3168
[*] Debugger Attached to PID 3168
[+] Event Code: 3 Thread ID: 5056
[+] Event Code: 6 Thread ID: 5056
[+] Event Code: 2 Thread ID: 8340
[+] Event Code: 2 Thread ID: 10020
[+] Event Code: 2 Thread ID: 4788
[+] Event Code: 2 Thread ID: 7572
[+] Event Code: 2 Thread ID: 128
[+] Event Code: 2 Thread ID: 7760
[+] Event Code: 2 Thread ID: 9552
[+] Event Code: 2 Thread ID: 4676
[+] Event Code: 2 Thread ID: 4516
[+] Event Code: 2 Thread ID: 8704
[+] Event Code: 2 Thread ID: 6016
[+] Event Code: 2 Thread ID: 8556
[+] Event Code: 2 Thread ID: 8968
[+] Event Code: 2 Thread ID: 8204
[+] Event Code: 2 Thread ID: 5444
```

### Set Breakpoint
```
$dwpid = Read-Host "Enter the PID of the Process to attach to"
attach -dwpid $dwpid
$address = func_resolve -dll "msvcrt.dll" -func "printf"
bp_set -address $address
run

detach
```

Output
```
Enter the PID of the Process to attach to: 4644
[*] Debugger Attached to PID 4644
[*] Set Breakpoint at 0x00116046
[+] Event Code: 3 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 2 Thread ID: 3268
[+] Event Code: 2 Thread ID: 9864
[+] Event Code: 2 Thread ID: 9700
[+] Event Code: 2 Thread ID: 6600
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 6 Thread ID: 7740
[+] Event Code: 2 Thread ID: 7288
[+] Event Code: 1 Thread ID: 7288
[+] Exception address: 0x00116046
[+] Event Code: 4 Thread ID: 7288
```
