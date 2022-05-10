# SetRDScertificate
Check, configure or update the Remote Desktop TLS configuration for a custom server authentication certificate from 'My' certificate space

https://docs.microsoft.com/en-us/troubleshoot/windows-server/remote/custom-server-authentication-certificate-for-tls describes how to use an existing certificate from a Windows machine 'My' certificate space as Remote Desktop Services certificate.
The script automates the process and checks if no default RDS existsts and picks the longest running, valid, server authentication enabled certificate that is not self-issued and adds it to the described registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp.
The script is tested on Windows Server 2019. 
