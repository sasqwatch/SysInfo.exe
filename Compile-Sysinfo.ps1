function Compile-SysInfo {
<#
.SYNOPSIS

	Compiles a .NET Assembly that gathers information about the system. Will drop a "SysInfo.exe" in C:\windows\temp. When executed, will write results to C:\windows\temp\SysInfo.txt.
	
	Gathers the following information:
	
	- Basic OS information
	- Environment
	- Achitecture
	- Users
	- Local Admins
	- Domain Admins
	- Current User Privileges
	- HotFixes
	- Check admin for current process
	- Share/Drives
	- Who's logged on
	- Installed Applications
	- Processes
	- Services
	- Tasks
	- Installed AV
	- Local DNS Client Cache
	- PowerShell Console History
	- Recently Accessed Documents
	- Network Interfaces
	- Network Connections
	
	
.EXAMPLE

	PS> . .\Compile-SysInfo.ps1
	PS> Compile-SysInfo
	
	
#>
	$FWDir = $([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())
	$SmaDll = [PSObject].Assembly.Location
	$CsFile = "$env:temp\$Z.cs"
	$Compiler = "$FWDir" + "c?c.??e"
	$CompilerArgs = "/r:$SmaDll /t:exe /out:C:\windows\temp\SysInfo.exe $CsFile"

	if ($(Test-Path $Compiler)) {
	
		$Source = @"
using System.Collections.ObjectModel;
using System.Management.Automation;
using System;
using System.IO;

namespace SysInfo
{
    class SysInfo
    {
        static void Main(string[] args)
        {
            using (PowerShell P = PowerShell.Create().AddScript(@"
			
Write-Output ""`n--- OS Information: ---"" | Out-File C:\windows\temp\SysInfo.txt
(get-wmiobject win32_operatingsystem | Select-Object Caption, Version, OSArchitecture, ServicePackMajorVersion, ServicePackMinorVersion, MUILanguages, LastBootUpTime, LocalDateTime, NumberOfUsers, SystemDirectory | Out-File -Append C:\windows\temp\SysInfo.txt)

Write-Output ""`n--- Environment: ---"" | Out-File -Append C:\windows\temp\SysInfo.txt
(Get-ChildItem Env: | ft Key,Value | Out-File -Append C:\windows\temp\SysInfo.txt)

Write-Output ""`n--- Architecture: ---"" | Out-File -Append C:\windows\temp\SysInfo.txt
(Get-WmiObject -Query ""SELECT * FROM Win32_Processor WHERE AddressWidth='64'"" | Out-File -Append C:\windows\temp\SysInfo.txt)

Write-Output ""`n--- Users: ---"" | Out-File -Append C:\windows\temp\SysInfo.txt
(Get-WmiObject -Class Win32_UserAccount -Filter  ""LocalAccount='True'"" | select name, fullname | Out-File -Append C:\windows\temp\SysInfo.txt)

Write-Output ""`n--- Local Admins: ---"" | Out-File -Append C:\windows\temp\SysInfo.txt
(C:\??*?\*3?\n?t.?x? localgroup Administrators | Out-File -Append C:\windows\temp\SysInfo.txt)

Write-Output ""`n--- Domain Admins: ---"" | Out-File -Append C:\windows\temp\SysInfo.txt
(C:\??*?\*3?\n?t.?x? group 'Domain Admins' /domain | Out-File -Append C:\windows\temp\SysInfo.txt)

Write-Output ""`n--- Privileges: ---"" | Out-File -Append C:\windows\temp\SysInfo.txt
(C:\??*?\*3?\wh??m?.?x? /priv | Out-File -Append C:\windows\temp\SysInfo.txt)

Write-Output ""`n--- HotFixes: ---"" | Out-File -Append C:\windows\temp\SysInfo.txt
(Get-Hotfix | Sort-Object -Descending | Out-File -Append C:\windows\temp\SysInfo.txt)

Write-Output ""`n--- Check Elevated: ---"" | Out-File -Append C:\windows\temp\SysInfo.txt
`$check = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match ""S-1-5-32-544"")
		if (`$check -eq `$true) {

			Write-Output "" [+] We're running as an elevated process."" | Out-File -Append C:\windows\temp\SysInfo.txt

		}
		if (`$check -eq `$false) {

			Write-Output "" [-] Not Elevated."" | Out-File -Append C:\windows\temp\SysInfo.txt
		}
		
Write-Output ""`n--- Shares/Drives: ---"" | Out-File -Append C:\windows\temp\SysInfo.txt
(Get-WmiObject Win32_Share | Out-File -Append C:\windows\temp\SysInfo.txt)

Write-Output ""`n--- Logged On: ---"" | Out-File -Append C:\windows\temp\SysInfo.txt
`$Explorer = (Get-WmiObject -Query ""select * from Win32_Process where Name='explorer.exe'"")
	
		if (!`$Explorer) {

		Write "" [-] No users currently interactively logged on."" | Out-File -Append C:\windows\temp\SysInfo.txt

		}
			else {
				foreach (`$p in `$Explorer) {
				`$Username = `$p.GetOwner().User
				`$Domain = `$p.GetOwner().Domain

				Write "" User: `$Domain\`$Username`n Logon Time: `$(`$p.ConvertToDateTime(`$p.CreationDate))"" | Out-File -Append C:\windows\temp\SysInfo.txt

			}
		}
		
Write-Output ""`n--- Installed Applications: ---"" | Out-File -Append C:\windows\temp\SysInfo.txt
(Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | Format-Table Parent,Name,LastWriteTime | Out-File -Append C:\windows\temp\SysInfo.txt)

Write-Output ""`n--- Processes: ---"" | Out-File -Append C:\windows\temp\SysInfo.txt
(Get-WmiObject -Query 'Select * from Win32_Process' | where {`$_.Name -notlike 'svchost*'} | Select Name, Handle, @{Label='Owner';Expression={`$_.GetOwner().User}} | Format-Table -AutoSize | Out-File -Append C:\windows\temp\SysInfo.txt)

Write-Output ""`n--- Services: ---"" | Out-File -Append C:\windows\temp\SysInfo.txt
(Get-WmiObject win32_service | Select-Object Name, DisplayName, @{Name=""Path""; Expression={`$_.PathName.split('""')[1]}}, State | Format-List | Out-File -Append C:\windows\temp\SysInfo.txt)

Write-Output ""`n--- Tasks: ---"" | Out-File -Append C:\windows\temp\SysInfo.txt
(Get-ChildItem C:\windows\system32\tasks |fl -Property Name,FullName | Out-File -Append C:\windows\temp\SysInfo.txt)

Write-Output ""`n--- Installed AV: ---"" | Out-File -Append C:\windows\temp\SysInfo.txt
[parameter(ValueFromPipeline=`$true, ValueFromPipelineByPropertyName=`$true)]
	[Alias('name')]
	`$computername=`$env:computername
	`$AntiVirusProducts = Get-WmiObject -Namespace ""root\SecurityCenter2"" -Class AntiVirusProduct  -ComputerName `$computername

		`$ret = @()
		foreach(`$AntiVirusProduct in `$AntiVirusProducts){
			switch (`$AntiVirusProduct.productState) {
			""262144"" {`$defstatus = ""Up to date"" ;`$rtstatus = ""Disabled""}
			""262160"" {`$defstatus = ""Out of date"" ;`$rtstatus = ""Disabled""}
			""266240"" {`$defstatus = ""Up to date"" ;`$rtstatus = ""Enabled""}
			""266256"" {`$defstatus = ""Out of date"" ;`$rtstatus = ""Enabled""}
			""393216"" {`$defstatus = ""Up to date"" ;`$rtstatus = ""Disabled""}
			""393232"" {`$defstatus = ""Out of date"" ;`$rtstatus = ""Disabled""}
			""393488"" {`$defstatus = ""Out of date"" ;`$rtstatus = ""Disabled""}
			""397312"" {`$defstatus = ""Up to date"" ;`$rtstatus = ""Enabled""}
			""397328"" {`$defstatus = ""Out of date"" ;`$rtstatus = ""Enabled""}
			""397584"" {`$defstatus = ""Out of date"" ;`$rtstatus = ""Enabled""}
			default {`$defstatus = ""Unknown"" ;`$rtstatus = ""Unknown""}
			}
			`$ht = @{}
			`$ht.Computername = `$computername
			`$ht.Name = `$AntiVirusProduct.displayName
			`$ht.'Product GUID' = `$AntiVirusProduct.instanceGuid
			`$ht.'Product Executable' = `$AntiVirusProduct.pathToSignedProductExe
			`$ht.'Reporting Exe' = `$AntiVirusProduct.pathToSignedReportingExe
			`$ht.'Definition Status' = `$defstatus
			`$ht.'Real-time Protection Status' = `$rtstatus

			`$ret += New-Object -TypeName PSObject -Property `$ht
		}
`$ret | Out-File -Append C:\windows\temp\SysInfo.txt

Write-Output ""`n--- Local Client DNS Cache: ---"" | Out-File -Append C:\windows\temp\SysInfo.txt
if (`$PSVersionTable.PSVersion.Major -eq ""2"") {

			Write "" [!] This function requires PowerShell version greater than 2.0."" | Out-File -Append C:\windows\temp\SysInfo.txt

			return
		}
		else {
			(Get-DnsClientCache | Out-File -Append C:\windows\temp\SysInfo.txt)
		}

Write-Output ""`n--- PowerShell ConsoleHost History: ---"" | Out-File -Append C:\windows\temp\SysInfo.txt	
(Get-Content ""`$env:appdata\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"" | Out-File -Append C:\windows\temp\SysInfo.txt)

Write-Output ""`n--- Recent Documents: ---"" | Out-File -Append C:\windows\temp\SysInfo.txt	
(Get-ChildItem `$env:appdata\Microsoft\Windows\Recent\ | Out-File -Append C:\windows\temp\SysInfo.txt)

Write-Output ""`n--- Network Interfaces: ---"" | Out-File -Append C:\windows\temp\SysInfo.txt	
(ipconfig /all | Out-File -Append C:\windows\temp\SysInfo.txt)

Write-Output ""`n--- Network Connections: ---"" | Out-File -Append C:\windows\temp\SysInfo.txt	
(netstat -an | Out-File -Append C:\windows\temp\SysInfo.txt)

"))
            {
                Collection<PSObject> Output = P.Invoke();
            }
		string text = System.IO.File.ReadAllText(@"C:\\windows\\temp\\SysInfo.txt");
		// System.Console.WriteLine("{0}", text);
		Console.WriteLine("SysInfo saved to C:\\windows\\temp\\SysInfo.txt");
		// System.Console.ReadLine();
		// System.IO.File.Delete("C:\\windows\\temp\\$Z");
        }
    }
}
"@

		New-Item "$env:temp\$Z.cs" -ItemType File >$null 2>&1
		Add-Content $CsFile $Source
		Start-Process -Wi Hidden -FilePath $Compiler -ArgumentList $CompilerArgs
		Sleep 4
		Remove-Item $env:temp\$Z.cs
		Write "`n [+] Assembly --> C:\windows\temp\SysInfo.exe`n"
	}
	else {
		Write-Output "Can't find compiler."
	}
}
