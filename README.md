# Cylance-Advanced-Query-Threat-Hunting

### MITRE ATT&CK Framework - Aligned Queries for Threat Hunting

---

#### **Initial Access**

1. **Attempt to Install Kali Linux via WSL**
   - **Query:**
     ```sql
     process where process.name == "wsl.exe" and process.command_line like~ "* kali *"
     ```
   - **MITRE ID:** [T1072](https://attack.mitre.org/techniques/T1072/)
   - **Description:** Detects attempts to install Kali Linux via Windows Subsystem for Linux (WSL).

2. **Browser Extension Install**
   - **Query:**
     ```sql
     file where file.path like~ "*.crx" or file.path like~ "*.xpi"
     ```
   - **MITRE ID:** [T1176](https://attack.mitre.org/techniques/T1176/)
   - **Description:** Monitors for the installation of browser extensions.

---

#### **Execution**

1. **Services.exe launching scripting engine**
   - **Query:**
     ```sql
     process where process.name in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe") and process.parent.name like~ "services.exe"
     ```
   - **MITRE ID:** [T1059](https://attack.mitre.org/techniques/T1059/)
   - **Description:** Identifies instances where `services.exe` spawns scripting engines such as cmd, PowerShell, and others.

2. **Visual basic script run via CMD**
   - **Query:**
     ```sql
     process where process.name like~ "cmd.exe" and process.command_line like~ "*cscript*"
     ```
   - **MITRE ID:** [T1059.005](https://attack.mitre.org/techniques/T1059/005/)
   - **Description:** Monitors for the execution of Visual Basic scripts via the command line.

3. **LOLBAS all activity**
   - **Query:**
     ```sql
     process where process.name in("bitsadmin.exe", "csvde.exe", "dsquery.exe", "ftp.exe", "makecab.exe", "nbtstat.exe", "net1.exe", "netstat.exe", "nslookup.exe", "ping.exe", "quser.exe", "route.exe", "schtasks.exe", "taskkill.exe", "tasklist.exe", "whoami.exe", "xcopy.exe", "psexec.exe")
     ```
   - **MITRE ID:** [T1218](https://attack.mitre.org/techniques/T1218/)
   - **Description:** Tracks the usage of Living Off The Land Binaries and Scripts (LOLBAS), which are legitimate system tools often used for malicious purposes.

4. **Executable running from C:\Windows\Temp**
    - **Query:**
      ```sql
      process where process.command_line like~ "C:\\Windows\\Temp\\*.exe"
      ```
    - **MITRE ID:** [T1074](https://attack.mitre.org/techniques/T1074/)
    - **Description:** Monitors for executables running from the Windows Temp directory.

5. **PowerShell Base64 Command**
   - **Query:**
     ```sql
     process where process.command_line regex~ ".*powershell.*[--]+[Ee^]{12}[NnCcOoDdEeMmAa^]+ [A-Za-z0-9+/=]{5}"
     ```
   - **MITRE ID:** [T1027](https://attack.mitre.org/techniques/T1027/)
   - **Description:** Detects the use of Base64 encoded commands in PowerShell.

---

6. **Control Panel Items**
   - **Query:**
     ```sql
     process where process.name in ("control.exe", "rundl132.exe") and process.command_line like~ "*.cpl *"
     ```
   - **MITRE ID:** [T1218.002](https://attack.mitre.org/techniques/T1218/002/)
   - **Description:** Detects execution of Control Panel items using `control.exe` or `rundl132.exe` with `.cpl` files.

7. **Mshta execution**
   - **Query:**
     ```sql
     process where process.name == "mshta.exe" and process.command_line like~ "*.hta*"
     ```
   - **MITRE ID:** [T1218.005](https://attack.mitre.org/techniques/T1218/005/)
   - **Description:** Detects the execution of HTA files using `mshta.exe`.

8. **BITS Jobs Execution**
   - **Query:**
     ```sql
     process where process.name == "bitsadmin.exe" and process.command_line like~ "* /TRANSFER *"
     ```
   - **MITRE ID:** [T1197](https://attack.mitre.org/techniques/T1197/)
   - **Description:** Monitors for the use of `bitsadmin.exe` to create BITS jobs.

9. **Wscript Execution**
   - **Query:**
     ```sql
     process where process.name == "wscript.exe" and process.command_line like~ "*.vbs*"
     ```
   - **MITRE ID:** [T1059.005](https://attack.mitre.org/techniques/T1059/005/)
   - **Description:** Detects the execution of VBScript files using `wscript.exe`.

10. **Certutil.exe Execution**
   - **Query:**
     ```sql
     process where process.name == "certutil.exe" and process.command_line like~ "* -encode *"
     ```
   - **MITRE ID:** [T1140](https://attack.mitre.org/techniques/T1140/)
   - **Description:** Identifies the use of `certutil.exe` to encode files.

11. **Scripting - PowerShell Trace**
   - **Query:**
     ```sql
     scripting where powershell_trace.event_id in (7937, 4103, 4104)
     ```
   - **MITRE ID:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/)
   - **Description:** Detects specific PowerShell events indicative of script execution.

12. **Scripting - General Script Execution**
   - **Query:**
     ```sql
     scripting where event.subcategory != "powershell" and event.type in ("execute script", "prevent script")
     ```
   - **MITRE ID:** [T1059](https://attack.mitre.org/techniques/T1059/)
   - **Description:** Identifies the execution of non-PowerShell scripts.

13. **Scripting - MITRE Techniques**
   - **Query:**
     ```sql
     scripting where event.mitre.techniques.name like~ "*"
     ```
   - **MITRE ID:** [T1059](https://attack.mitre.org/techniques/T1059/)
   - **Description:** Monitors for scripting events tagged with MITRE techniques.

14. **PowerShell Process Injection**
   - **Query:**
     ```sql
     process where process.name == "powershell.exe" and event.type == "process handle opened"
     ```
   - **MITRE ID:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/)
   - **Description:** Detects process injection attempts using PowerShell.

15. **Inter-Process Communication via Xwizard**
   - **Query:**
     ```sql
     process where process.file.path like~ "*xwizard.exe" and process.command_line like~ "*Runwizard*"
     ```
   - **MITRE ID:** [T1559](https://attack.mitre.org/techniques/T1559/)
   - **Description:** Monitors for the use of `xwizard.exe` to facilitate inter-process communication.
---

#### **Persistence**

1. **Startup Folder Persistence**
   - **Query:**
     ```sql
     file where file.path like~ "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*.lnk"
     ```
   - **MITRE ID:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/)
   - **Description:** Monitors for the creation of shortcut files (`.lnk`) in the startup folder.

2. **Scheduled Task Creation**
   - **Query:**
     ```sql
     process where process.name like~ "schtasks.exe" and process.command_line like~ "* /create *"
     ```
   - **MITRE ID:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/)
   - **Description:** Detects the creation of scheduled tasks via `schtasks.exe`.


3. **Office Macros**
   - **Query:**
     ```sql
     process where process.name in ("winword.exe", "excel.exe", "powerpnt.exe") and process.command_line like~ "*.docm *.xlsm *.pptm"
     ```
   - **MITRE ID:** [T1137](https://attack.mitre.org/techniques/T1137/)
   - **Description:** Monitors for the execution of Office documents with macros enabled.

4. **Registry Run Keys**
   - **Query:**
     ```sql
     registry where registry.path == "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" and registry.value_name like~ "*"
     ```
   - **MITRE ID:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/)
   - **Description:** Detects the creation of registry run keys for persistence.

---

#### **Privilege Escalation**

1. **Process where event.mitre.tactics.name like~"* Privilege Escalation *"**
   - **Query:**
     ```sql
     process where event.mitre.tactics.name like~"* Privilege Escalation *"
     ```
   - **MITRE ID:** [TA0004](https://attack.mitre.org/tactics/TA0004/)
   - **Description:** General query for detecting any events related to privilege escalation tactics.

2. **Process where process.name == "elevation service.exe" and process.file.path regex-"(?!.*\\elevation service).*$"**
   - **Query:**
     ```sql
     process where process.name == "elevation service.exe" and process.file.path regex-"(?!.*\\elevation service).*$"
     ```
   - **MITRE ID:** [T1055](https://attack.mitre.org/techniques/T1055/)
   - **Description:** Detects the execution of the `elevation service.exe` process from unexpected locations.

3. **Process where process.name in ("rundl132.exe", "cmd.exe", "powershell.exe") and process.parent.name == "elevation service.exe"**
   - **Query:**
     ```sql
     process where process.name in ("rundl132.exe", "cmd.exe", "powershell.exe") and process.parent.name == "elevation service.exe"
     ```
   - **MITRE ID:** [T1055](https://attack.mitre.org/techniques/T1055/)
   - **Description:** Monitors for suspicious child processes spawned by `elevation service.exe`.

4. **New Local User added or user added to administrators**
   - **Query:**
     ```sql
     process where process.command_line in~ ("*net user /add*", "*New-LocalUser*", "*net localgroup administrators*")
     ```
   - **MITRE ID:** [T1136.001](https://attack.mitre.org/techniques/T1136/001/)
   - **Description:** Detects commands used to create new local users or add users to the administrators group.

---

#### **Defense Evasion**

1. **Windows event logs cleared**
   - **Query:**
     ```sql
     process where process.command_line like~ "wevtutil* cl*"
     ```
   - **MITRE ID:** [T1070.001](https://attack.mitre.org/techniques/T1070/001/)
   - **Description:** Detects the use of `wevtutil` to clear Windows event logs.

2. **Certutil used to encrypt or decrypt files**
   - **Query:**
     ```sql
     process where process.command_line in~("certutil* -encode*", "certutil* -decode*")
     ```
   - **MITRE ID:** [T1140](https://attack.mitre.org/techniques/T1140/)
   - **Description:** Detects the use of `certutil` for encoding or decoding files.

3. **Command prompt used to disable Windows Firewall**
   - **Query:**
     ```sql
     process where process.command_line like~ "netsh* advfirewall* set* currentprofile* state* off*"
     ```
   - **MITRE ID:** [T1562.004](https://attack.mitre.org/techniques/T1562/004/)
   - **Description:** Identifies the use of `netsh` to disable Windows Firewall.

4. **Powershell used to clear event logs**
   - **Query:**
     ```sql
     scripting where powershell_trace.script_block like~ "*Clear-EventLog*"
     ```
   - **MITRE ID:** [T1070.001](https://attack.mitre.org/techniques/T1070/001/)
   - **Description:** Detects the use of PowerShell to clear event logs.

5. **Disabling Security Tools**
   - **Query:**
     ```sql
     process where process.name in("taskkill.exe", "wmic.exe") and process.command_line like~ "* /F /IM *"
     ```
   - **MITRE ID:** [T1562.001](https://attack.mitre.org/techniques/T1562/001/)
   - **Description:** Detects the use of `taskkill` or `wmic` to forcefully terminate security tools.

6. **Timestomping**
   - **Query:**
     ```sql
     process where process.name == "attrib.exe" and process.command_line like~ "* +A +R +S +H *"
     ```
   - **MITRE ID:** [T1070.006](https://attack.mitre.org/techniques/T1070/006/)
   - **Description:** Monitors for the use of `attrib.exe` to change file attributes.

7. **Command Line Obfuscation**
   - **Query:**
     ```sql
     process where process.command_line regex~ ".*\\^.*\\&.*\\|.*"
     ```
   - **MITRE ID:** [T1027](https://attack.mitre.org/techniques/T1027/)
   - **Description:** Detects obfuscated command lines using characters like `^`, `&`, and `|`.

8. **Image File Execution Options Injection**
   - **Query:**
     ```sql
     registry where registry.path like~ "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*.exe" and registry.value_name == "Debugger"
     ```
   - **MITRE ID:** [T1546.012](https://attack.mitre.org/techniques/T1546/012/)
   - **Description:** Monitors for modifications to Image File Execution Options (IFEO) registry keys to hijack executables.

9. **Encoded PowerShell Commands**
   - **Query:**
     ```sql
     process where process.command_line like~ "*powershell* -encodedcommand *"
     ```
   - **MITRE ID:** [T1027.001](https://attack.mitre.org/techniques/T1027/001/)
   - **Description:** Detects the use of encoded commands in PowerShell.
  
10. **Potential Evasion via Filter Manager**
   - **Query:**
     ```sql
     process where process.name == "fltMC.exe" and process.command_line like~ "* unload *"
     ```
   - **MITRE ID:** [T1562](https://attack.mitre.org/techniques/T1562/)
   - **Description:** Detects the use of `fltMC.exe` to unload filter drivers, a potential evasion technique.

11. **Bypass UAC via Event Viewer**
   - **Query:**
     ```sql
     process where process.parent.name == "eventvwr.exe" and process.name not in ("mmc.exe")
     ```
   - **MITRE ID:** [T1088](https://attack.mitre.org/techniques/T1088/)
   - **Description:** Detects potential UAC bypass attempts using Event Viewer.

12. **Command Line Obfuscation**
   - **Query:**
     ```sql
     process where process.name == "cmd.exe" and process.command_line like~ "* copy *//b *"
     ```
   - **MITRE ID:** [T1027](https://attack.mitre.org/techniques/T1027/)
   - **Description:** Identifies obfuscated command line usage to evade detection.

13. **Processes Running Without Command Line**
   - **Query:**
     ```sql
     process where process.name in ("backgroundtaskhost.exe", "svchost.exe", "dllhost.exe", "werfault.exe", "searchprotocolhost.exe", "wuauclt.exe", "spoolsv.exe", "rund1132.exe", "regasm.exe", "regsvr32.exe", "regsvcs.exe") and process.command_line == ""
     ```
   - **MITRE ID:** [T1036](https://attack.mitre.org/techniques/T1036/)
   - **Description:** Detects processes running without command line arguments, which can indicate masquerading.

14. **System Binary Proxy Execution - CHM Files**
   - **Query:**
     ```sql
     process where process.name == "hh.exe"
     ```
   - **MITRE ID:** [T1218.001](https://attack.mitre.org/techniques/T1218/001/)
   - **Description:** Monitors for the execution of compiled HTML files using `hh.exe`.

     
---

#### **Credential Access**

1. **Credential Dumping - LSASS**
   - **Query:**
     ```sql
     process where process.name == "procdump.exe" and process.command_line regex~ ".* -ma (?!.*\\lsass\\.dmp) (lsass.exe)"
     ```
   - **MITRE ID:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/)
   - **Description:** Detects the use of `procdump` for dumping the memory of `lsass.exe`.

2. **Pass-the-Hash - Impacket**
   - **Query:**
     ```sql
     process where process.name == "wmiexec.py" and process.command_line regex~ ".* -target .* -u .* -hashes .*"
     ```
   - **MITRE ID:** [T1075](https://attack.mitre.org/techniques/T1075/)
   - **Description:** Detects the use of Impacket's `wmiexec` tool for pass-the-hash attacks.

3. **Mimikatz Execution**
   - **Query:**
     ```sql
     process where process.name == "mimikatz.exe" or process.command_line like~ "*sekurlsa::logonpasswords*"
     ```
   - **MITRE ID:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/)
   - **Description:** Detects the execution of Mimikatz, a tool used for credential dumping.

4. **Dumping NTDS.dit**
   - **Query:**
     ```sql
     process where process.command_line like~ "*esentutl* /y* /d* /o*"
     ```
   - **MITRE ID:** [T1003.003](https://attack.mitre.org/techniques/T1003/003/)
   - **Description:** Identifies the use of `esentutl` for dumping the NTDS.dit file.
  
5. **Scripting - Credential Access via PowerShell**
   - **Query:**
     ```sql
     process where process.name == "powershell.exe" and process.command_line like~ ("*invoke-expression*", "*iex*", "*downloadstring*", "*downloadfile*")
     ```
   - **MITRE ID:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/)
   - **Description:** Detects PowerShell commands indicative of credential access attempts. 
---

#### **Discovery**

1. **LOLB

AS all activity**
   - **Query:**
     ```sql
     process where process.name in("bitsadmin.exe", "csvde.exe", "dsquery.exe", "ftp.exe", "makecab.exe", "nbtstat.exe", "net1.exe", "netstat.exe", "nslookup.exe", "ping.exe", "quser.exe", "route.exe", "schtasks.exe", "taskkill.exe", "tasklist.exe", "whoami.exe", "xcopy.exe", "psexec.exe")
     ```
   - **MITRE ID:** [T1087](https://attack.mitre.org/techniques/T1087/)
   - **Description:** Tracks the usage of Living Off The Land Binaries and Scripts (LOLBAS).

2. **PowerShell network discovery commands**
   - **Query:**
     ```sql
     process where process.name == "powershell.exe" and process.command_line like~ "*Get-NetIPAddress*"
     ```
   - **MITRE ID:** [T1046](https://attack.mitre.org/techniques/T1046/)
   - **Description:** Detects network discovery commands executed via PowerShell.

3. **Net Command Execution**
   - **Query:**
     ```sql
     process where process.name == "net.exe" and process.command_line like~ "* user *"
     ```
   - **MITRE ID:** [T1087.001](https://attack.mitre.org/techniques/T1087/001/)
   - **Description:** Detects the use of the `net` command to enumerate user accounts.

4. **Network Share Enumeration**
   - **Query:**
     ```sql
     process where process.name == "net.exe" and process.command_line like~ "* share *"
     ```
   - **MITRE ID:** [T1135](https://attack.mitre.org/techniques/T1135/)
   - **Description:** Monitors for the enumeration of network shares using the `net` command.
  
 5. **Command and Scripting Interpreter - Network Connection**
   - **Query:**
     ```sql
     network where process.name == "cmd.exe"
     ```
   - **MITRE ID:** [T1059](https://attack.mitre.org/techniques/T1059/)
   - **Description:** Identifies `cmd.exe` making a network connection.

 6. **Command and Scripting Interpreter - Suspicious Parent-Child Process Relationship**
   - **Query:**
     ```sql
     process where process.name == "cmd.exe" and process.parent.name in ("lsass.exe", "csrss.exe", "epad.exe", "regsvr32.exe", "dllhost.exe", "LogonUI.exe", "wermgr.exe", "spoolsv.exe", "jucheck.exe", "jusched.exe", "ctfmon.exe", "taskhostw.exe", "Googleupdate.exe", "sppsvc.exe", "sihost.exe", "slui.exe", "SIHClient.exe", "SearchIndexer.exe", "SearchProtocolHost.exe", "FlashPlayerUpdateService.exe", "WerFault.exe", "WUDFHost.exe", "unsecapp.exe", "wlanext.exe")
     ```
   - **MITRE ID:** [T1059](https://attack.mitre.org/techniques/T1059/)
   - **Description:** Identifies suspicious parent-child process relationships involving `cmd.exe`.    
---

#### **Lateral Movement**

1. **Remote PowerShell Execution**
   - **Query:**
     ```sql
     process where process.name == "powershell.exe" and process.command_line like~ "*-Command*Invoke-Command*"
     ```
   - **MITRE ID:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/)
   - **Description:** Detects remote execution of PowerShell commands.

2. **WMI Remote Execution**
   - **Query:**
     ```sql
     process where process.name == "wmiprvse.exe" and process.command_line like~ "*Create*CommandLine*"
     ```
   - **MITRE ID:** [T1047](https://attack.mitre.org/techniques/T1047/)
   - **Description:** Monitors for remote command execution via WMI.
  
3. **SMB Connection Attempt**
   - **Query:**
     ```sql
     network where network.protocol == "SMB" and network.destination_port == 445
     ```
   - **MITRE ID:** [T1021.002](https://attack.mitre.org/techniques/T1021/002/)
   - **Description:** Identifies SMB connection attempts, which can be used for lateral movement.

4. **Remote Desktop Connection**
   - **Query:**
     ```sql
     network where network.protocol == "RDP" and network.destination_port == 3389
     ```
   - **MITRE ID:** [T1021.001](https://attack.mitre.org/techniques/T1021/001/)
   - **Description:** Monitors for RDP connections to detect potential lateral movement via Remote Desktop Protocol.

---

#### **Collection**

1. **File transfer to network share**
   - **Query:**
     ```sql
     file where file.name like~ "C:\\Users\\%USERNAME%\\Documents\\*.docx" and file.network.path like~ "\\\\sharedrive\\files\\*"
     ```
   - **MITRE ID:** [T1530](https://attack.mitre.org/techniques/T1530/)
   - **Description:** Monitors for the transfer of documents to network shares.
  
2.  **Executable File Creation with Multiple Extensions**
   - **Query:**
     ```sql
     file where file.path regex~ ".*[.](?:vbs|vbe|bat|js|cmd|wsh|ps1?|pdf|docx?|xlsx?|pptx?|txt|rtf|gif|jpg|png|bmp|hta|txt|img|iso|zip)[.]exe"
     ```
   - **MITRE ID:** [T1566](https://attack.mitre.org/techniques/T1566/)
   - **Description:** Detects the creation of executable files with multiple extensions.


---

#### **Command and Control**

1. **Remote Access Tool Execution**
   - **Query:**
     ```sql
     process where process.name in("TeamViewer.exe", "AnyDesk.exe", "RemoteDesktop.exe") and process.parent.name == "explorer.exe"
     ```
   - **MITRE ID:** [T1219](https://attack.mitre.org/techniques/T1219/)
   - **Description:** Detects the execution of known remote access tools.
  
2.  **Cobalt Strike Beacon Detection**
   - **Query:**
     ```sql
     network where http.request.domain regex~ "[a-z]{3}\.stage\.[0-9]{8}\."
     ```
   - **MITRE ID:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/)
   - **Description:** Identifies HTTP requests consistent with Cobalt Strike beacons.

---

#### **Exfiltration**

1. **File Transfer to External Hosts**
   - **Query:**
     ```sql
     network where network.protocol == "FTP" and network.destination.address not in~("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
     ```
   - **MITRE ID:** [T1048](https://attack.mitre.org/techniques/T1048/)
   - **Description:** Monitors FTP file transfers to external IP addresses.

2. **Suspicious HTTP Post Request**
   - **Query:**
     ```sql
     network where network.http.method == "POST" and network.http.uri_path regex~ "/(upload|data|transfer|send)"
     ```
   - **MITRE ID:** [T1041](https://attack.mitre.org/techniques/T1041/)
   - **Description:** Detects suspicious HTTP POST requests.

---
