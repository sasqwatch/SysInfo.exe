# SysInfo.exe

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
  ### Usage:
  
  PS> . .\Compile-SysInfo.ps1
  PS> Compile-SysInfo
