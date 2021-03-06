

using System.IO;
using System.Text;
using System;
using System.Security.Cryptography;

public class Encypt
{
	public static byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
	{
		byte[] encryptedBytes = null;
		byte[] saltBytes = new byte[] {1,2,3,4,5,6,7,8};
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

				using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
				{
					cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
					cs.Close();
					
				}
				encryptedBytes = ms.ToArray();

			}
		}

		return encryptedBytes;

	}

	public byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
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
	/*
	public static void PrintShellcode(string shellcodeBytes)
	{
		StringBuilder shellcode = new StringBuilder();
		shellcode.Append("byte[] shellcode = new byte [");
		shellcode.Append(shellcodeBytes.Length);
		shellcode.Append("] { ");
		for (int i = 0; i < shellcodeBytes.Length; i++)
		{
			shellcode.Append("0x");
			shellcode.AppendFormat("{o:x2}", shellcodeBytes[i]);
			if (i < shellcodeBytes.Length - 1)
			{
				shellcode.Append(",");
			}
		}
		shellcode.Append(" };");
		Console.WriteLine(shellcode);
	}
	*/
	public static void Main(string[] args)
	{
		if (args.Length == 0)
		{
			Console.WriteLine("[!] Usage: encrypt.exe <file>");
			return;
		}
		byte[] shellcode = File.ReadAllBytes(args[0]);
		string outputFile = args[0] + "_enc";
		byte[] password = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes("DtGvFck#"));
		Console.WriteLine("[<] Shellcode Length: {0} Bytes", shellcode.Length);
		byte[] shellcodeEncrypted = AES_Encrypt(shellcode, password);
		Console.WriteLine("[+] Encrypted shellcode Length: {0} Bytes", shellcodeEncrypted.Length);
		File.WriteAllBytes(outputFile, shellcodeEncrypted);
		//PrintShellcode(shellcodeEncrypted.ToString());
		
	}
}

