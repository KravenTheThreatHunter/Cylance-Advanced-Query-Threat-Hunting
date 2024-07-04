# Cylance-Advanced-Query-Threat-Hunting

### MITRE ATT&CK Framework - Aligned Queries for Threat Hunting

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

---

#### **Collection**

1. **File transfer to network share**
   - **Query:**
     ```sql
     file where file.name like~ "C:\\Users\\%USERNAME%\\Documents\\*.docx" and file.network.path like~ "\\\\sharedrive\\files\\*"
     ```
   - **MITRE ID:** [T1530](https://attack.mitre.org/techniques/T1530/)
   - **Description:** Monitors for the transfer of documents to network shares.

---

#### **Command and Control**

1. **Remote Access Tool Execution**
   - **Query:**
     ```sql
     process where process.name in("TeamViewer.exe", "AnyDesk.exe", "RemoteDesktop.exe") and process.parent.name == "explorer.exe"
     ```
   - **MITRE ID:** [T1219](https://attack.mitre.org/techniques/T1219/)
   - **Description:** Detects the execution of known remote access tools.

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
