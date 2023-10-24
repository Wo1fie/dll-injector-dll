using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;

namespace dll_injector
{
    public class DllInjector
    {
        #region Function Imports
        [DllImport("kernel32")]
        static extern int GetLastError();

        [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]
        private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]
        internal static extern int WaitForSingleObject(IntPtr handle, int milliseconds);

        [DllImport("kernel32")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, string lpBuffer, UIntPtr nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32")]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, UIntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true)]
        public static extern UIntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, int bInheritHandle, int dwProcessId);

        [DllImport("kernel32")]
        static extern bool CloseHandle(IntPtr hObject);
        #endregion
        public enum InjectReturnStatus { Success, OpenProcess, VirtualAllocEx, WriteProcessMemory, GetProcAddress, CreateRemoteThread, CloseHandle, VirtualFreeEx };

        Process _process;
        public DllInjector(Process process)
        {
            _process = process;
        }
        public InjectReturnStatus InjectDll(FileInfo dllFile)
        {
            return InjectDll(_process, dllFile);
        }
        public static InjectReturnStatus InjectDll(Process process, FileInfo dllFile)
        {
            IntPtr hProcess = OpenProcess(0x1f0fff, 1, process.Id);
            IntPtr ptr;
            int dllPathLength = dllFile.FullName.Length + 1;
            IntPtr lpBaseAddress = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)dllPathLength, 0x1000, 0x40);
            if (lpBaseAddress == IntPtr.Zero)
                return InjectReturnStatus.VirtualAllocEx;
            bool rawr = WriteProcessMemory(hProcess, lpBaseAddress, dllFile.FullName, (UIntPtr)dllPathLength, out ptr);
            if (!rawr)
                return InjectReturnStatus.WriteProcessMemory;
            UIntPtr procAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
            if (procAddress == UIntPtr.Zero)
                return InjectReturnStatus.GetProcAddress;
            IntPtr handle = CreateRemoteThread(hProcess, IntPtr.Zero, 0, procAddress, lpBaseAddress, 0, out ptr);
            if (handle == IntPtr.Zero)
                return InjectReturnStatus.CreateRemoteThread;

            switch ((long)WaitForSingleObject(handle, 0x2710))
            {
                case 0x80L:
                case 0x102L:
                case 0xffffffffL:
                    if (!CloseHandle(handle))
                        return InjectReturnStatus.CloseHandle;
                    break;
            }
            if (!VirtualFreeEx(hProcess, lpBaseAddress, (UIntPtr)0, 0x8000))
                return InjectReturnStatus.VirtualFreeEx;

            if (!CloseHandle(handle))
                return InjectReturnStatus.CloseHandle;
            return InjectReturnStatus.Success;
        }
    }
}
