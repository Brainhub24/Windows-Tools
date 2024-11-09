<#
.SYNOPSIS
    Manages Windows auto-login settings in the registry.

.DESCRIPTION
    This PowerShell script allows administrators to configure, check, and disable auto-login settings for a specified user on a Windows machine. It interacts directly with the Windows registry, setting parameters necessary for automatic login, making it ideal for controlled environments where auto-login is needed temporarily or for specific users.

.PARAMETER Action
    The action to perform. Acceptable values are:
      - "configure": Sets auto-login for the specified user.
      - "check": Displays current auto-login settings if they exist.
      - "disable": Disables auto-login.

.PARAMETER UserName
    The username for configuring auto-login. Required only when Action is set to "configure".

.PARAMETER Password
    The password for configuring auto-login. Required only when Action is set to "configure".

.EXAMPLE
    .\AutoLoginManager.ps1 -Action configure -UserName "Trump2025" -Password "T3000"
    Configures auto-login for "Trump2025" with the specified password.

    .\AutoLoginManager.ps1 -Action check
    Checks the current auto-login configuration, if any.

    .\AutoLoginManager.ps1 -Action disable
    Disables auto-login.

.NOTES
    Author: Brainhub24 - Jan Gebser
    URL: www.brainhub24.com
    Company: NETCORE MEDIA
    Department: Research and Development @WSD
    Date: 09.11.2024
    Version: 0.3.2

.USAGE
    # 1. **Run as Administrator**:
       Since this script modifies the registry, it requires administrator privileges. 
       To open PowerShell as an administrator:
       - Right-click on the PowerShell icon and select "Run as administrator", OR
       - Use the following
         Start-Process PowerShell -Verb RunAs

    # 2. **Bypass Execution Policy**:
       If your system’s execution policy prevents the script from running, you can bypass it temporarily:
       Set-ExecutionPolicy Bypass -Scope Process -Force
	   (https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.4)
	   
       This command applies the policy bypass only to the current PowerShell session, so your system's security settings will not be permanently changed.

    # 3. **Running the Script**:
       After opening PowerShell as an administrator and setting the execution policy (if needed), you can run the script with any of the actions:
       .\AutoLoginManager.ps1 -Action "configure" -UserName "Trump2025" -Password "T3000"

.DISCLAIMER
    This script modifies sensitive Windows registry settings, specifically for auto-login. It is meant for testing and controlled environments. Please ensure that the credentials provided are secure, and avoid using it on production systems without proper risk assessment.
#>


param (
    [string]$Action,    # @PARAM Action - The operation to be performed by the script: "configure" (enables auto-login), "check" (displays current settings), or "disable" (turns off auto-login)
    [string]$UserName,  # @PARAM UserName - The username required for setting up auto-login; only necessary if Action is set to "configure"
    [string]$Password   # @PARAM Password - The password corresponding to the UserName, necessary for "configure" Action to enable auto-login
)

# @CONSTANT regPath - Defines the registry path for auto-login settings in Windows; modifying values here directly influences login behavior
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Function: Configure-AutoLogin
# Purpose: Sets up Windows auto-login by configuring registry keys with specified username and password.
# Preconditions:
#   - Requires both UserName and Password parameters.
#   - Password will be stored in plain text (not secure for production use).
function Configure-AutoLogin {
    # Verify required parameters are provided before proceeding with configuration
    if (-not $UserName -or -not $Password) {
        Write-Host "Error: Both UserName and Password must be provided for auto-login configuration." -ForegroundColor Red
        return
    }

    # @NOTE Password Conversion - Converts the provided password to plain text for storage; plain text storage is discouraged for secure environments
    $plainPassword = [System.Net.NetworkCredential]::new("", (ConvertTo-SecureString -String $Password -AsPlainText -Force)).Password

    # Set registry values to configure auto-login behavior
    Set-ItemProperty -Path $regPath -Name "AutoAdminLogon" -Value "1"                  # Enables auto-login functionality
    Set-ItemProperty -Path $regPath -Name "DefaultUserName" -Value $UserName           # Sets username for auto-login session
    Set-ItemProperty -Path $regPath -Name "DefaultPassword" -Value $plainPassword      # Sets password for auto-login session
    Set-ItemProperty -Path $regPath -Name "DefaultDomainName" -Value "localhost"       # Sets domain to localhost if not part of a network domain

    Write-Host "Auto-login has been successfully configured for user $UserName."
}

# Function: Check-AutoLogin
# Purpose: Retrieves and displays current auto-login configuration status.
# Behavior:
#   - Checks if auto-login is enabled by reading registry values.
#   - Provides feedback if auto-login is not configured or registry access fails.
function Check-AutoLogin {
    try {
        # Retrieve values from the registry to assess auto-login configuration status
        $autoLoginUser = Get-ItemProperty -Path $regPath -Name "DefaultUserName" -ErrorAction Stop
        $autoLoginPassword = Get-ItemProperty -Path $regPath -Name "DefaultPassword" -ErrorAction Stop
        $autoLoginDomain = Get-ItemProperty -Path $regPath -Name "DefaultDomainName" -ErrorAction Stop
        $autoLoginStatus = Get-ItemProperty -Path $regPath -Name "AutoAdminLogon" -ErrorAction Stop

        # Check if auto-login is active; otherwise, notify user of disabled status
        if ($autoLoginStatus.AutoAdminLogon -eq "1") {
            Write-Host "Auto-login is enabled for user $($autoLoginUser.DefaultUserName) in domain $($autoLoginDomain.DefaultDomainName)."
        } else {
            Write-Host "Auto-login is currently not enabled."
        }
    } catch {
        # Error handling in case the registry keys are inaccessible or do not exist
        Write-Host "Error: Auto-login is either not configured or inaccessible." -ForegroundColor Red
    }
}

# Function: Disable-AutoLogin
# Purpose: Disables auto-login by clearing relevant registry entries.
# Behavior:
#   - Sets AutoAdminLogon to "0" to turn off auto-login.
#   - Clears any stored user, password, and domain values to prevent unintended auto-login.
function Disable-AutoLogin {
    try {
        # Update registry settings to effectively disable auto-login
        Set-ItemProperty -Path $regPath -Name "AutoAdminLogon" -Value "0"               # Disables auto-login by setting flag to "0"
        Set-ItemProperty -Path $regPath -Name "DefaultUserName" -Value ""               # Clears stored username
        Set-ItemProperty -Path $regPath -Name "DefaultPassword" -Value ""               # Clears stored password
        Set-ItemProperty -Path $regPath -Name "DefaultDomainName" -Value ""             # Clears stored domain

        Write-Host "Auto-login has been successfully disabled."
    } catch {
        # Error handling in case clearing registry settings encounters an issue
        Write-Host "Error: Failed to disable auto-login. Verify permissions or registry access." -ForegroundColor Red
    }
}

# Main Script Logic
# Executes the appropriate function based on the Action parameter value.
# Valid Actions:
#   - "configure": Calls Configure-AutoLogin; requires UserName and Password.
#   - "check": Calls Check-AutoLogin to display current status.
#   - "disable": Calls Disable-AutoLogin to turn off auto-login.
if ($Action -eq "configure") {
    # Verify that UserName and Password are provided for "configure" action
    if (-not $UserName -or -not $Password) {
        Write-Host "Error: Please provide both UserName and Password for auto-login configuration." -ForegroundColor Red
    } else {
        Configure-AutoLogin    # Call function to enable auto-login
    }
} elseif ($Action -eq "check") {
    # Call function to display current auto-login configuration
    Check-AutoLogin
} elseif ($Action -eq "disable") {
    # Call function to disable auto-login
    Disable-AutoLogin
} else {
    # Handle invalid Action parameter values by showing an error message
    Write-Host "Error: Invalid Action. Use 'configure', 'check', or 'disable'." -ForegroundColor Red
}
