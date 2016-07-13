# HatDBG
The goal of this project is to make a powershell debugger. This is exclusively for educational purposes.

### Eumerate Threads
```
#Use PID for attach debugger
$result = attach -dwpid 1832
if([bool] $result)
{
$list = enumerate_threads
foreach ($thread in $list){
	$thread_context = get_thread_context -thread_id $thread
	write-host "[+] Dumping register for thread ID: " $thread
	write-host "[+] EIP: " $thread_context.Eip
	write-host "[+] ESP: " $thread_context.Esp
	write-host "[+] EBP: " $thread_context.Ebp
	write-host "[+] EAX: " $thread_context.Eax
	write-host "[+] EBX: " $thread_context.Ebx
	write-host "[+] ECX: " $thread_context.Ecx
	write-host "[+] EDX: " $thread_context.Edx
	write-host "[+] END DUMP"
}
$result = detach
}
```
