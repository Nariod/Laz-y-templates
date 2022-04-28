# Laz-y templates
Laz-y project compatible C# templates for shellcode injection. These templates only make sense when used with https://github.com/Nariod/laz-y.

| Name | Technique | Arch compilation | OPSEC consideration | Comment |
| --- | --- | --- | --- | --- |
| bayraktar | QueueUserAPC injection | AnyCPU | Not stealthy at all | Injects shellcode by APC in all threads of all processes. You will likely end up with dozens of shells. |
| earlybird | QueueUserAPC injection | x64 | Quite stealthy | Starts a process in suspended mode, inject shellcode by APC and resume process. |
| apcqueue | QueueUserAPC injection | x64 | Stealthy | Inject shellcode by APC in threads of a few common running processes. |

## Usage
Add the wanted templates to the [laz-y](https://github.com/Nariod/laz-y) project "templates" folder.

## Credits
Credits are given in each file for the corresponding code. Special thanks to:
* Stackoverflow 
* https://www.ired.team/

## Legal disclaimer
Usage of anything presented in this repo to attack targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational purposes.