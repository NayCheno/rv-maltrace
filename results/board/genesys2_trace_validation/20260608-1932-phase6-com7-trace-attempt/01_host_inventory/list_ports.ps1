Get-PnpDevice -Class Ports -PresentOnly |
    Select-Object Status,FriendlyName,InstanceId |
    Format-Table -AutoSize

Get-ItemProperty -Path 'HKLM:\HARDWARE\DEVICEMAP\SERIALCOMM' |
    Format-List
