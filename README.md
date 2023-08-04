# Admin_Watchdog

## Overview

This PowerShell script continuously monitors the Windows Security log for Sensitive Privilege Use events (Event ID 4673) and filters out logs generated by `powershell.exe`. The script provides a real-time view of privilege use events while excluding internal PowerShell activities to focus on external events.

## Requirements

- Windows OS with PowerShell 7.1 or later.
- Audit Logon Events Enabled.
    - `auditpol.exe /set '/subcategory:{0CCE9228-69AE-11D9-BED3-505054503030}' /success:enable`
      - *Run in Powershell or add directly to script*


## Usage

1. Download the `Admin_Watchdog.ps1` script to your local system.

2. Open PowerShell with administrative privileges.

3. The script will continuously read and parse Sensitive Privilege Use events from the Security log.

4. It will display the relevant event information, excluding logs generated by `powershell.exe`.

5. The script will continue to run until you manually stop it using `Ctrl+C` or by terminating the PowerShell session.

## Configuration

- The script applies a filter to exclude logs generated by `powershell.exe` based on the `ProcessName` property.

- You can modify the `Start-Sleep` interval in the script to adjust the frequency of event checks.

## Important Note

- Continuous monitoring of the Security log may consume system resources over time. Monitor resource usage and consider running the script as a background task or service for extended use.
- If you get the error:
    - ```File \path\to\file cannot be loaded because running scripts is disabled on this system```
    - Run the script via this command: ```powershell -ExecutionPolicy Bypass -File script.ps1```
---

**Disclaimer:** This script is only provided for educational and informational purposes. Use it responsibly and ensure you have appropriate permissions to access and monitor Windows event logs.

Happy monitoring!
