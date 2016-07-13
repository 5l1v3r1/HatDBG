# HatDBG
The HatDBG is A pure Powershell win32 debugging abstraction class.The goal of this project is to make a powershell debugger. This is exclusively for educational purposes.

## Features
 + Register manipulation.
 + Soft (INT 3) breakpoints.
 + Memory breakpoints (page permissions).
 + Hardware breakpoints.
 + Exception / event handling call backs.
 + Process memory snapshotting and restoring.
 + Function resolution.
 + Stack/SEH unwinding.

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
