#Usage: get-scsilunpath.ps1 -Esx host1.domain.ru -Storage iqn.1992-08.com.netapp:sn.1234567890
param ($Esx, $Storage)

$dict=@{}
Get-Datastore | %{$dict[$_.extensiondata.info.vmfs.extent.diskname] = $_.name}
Get-ScsiLun -VmHost $Esx | get-scsilunpath | ? {$_.SanID -like $Storage} | select name, sanid, @{N="IP";E={$_.extensiondata.transport.address}}, @{N='Datastore';E={$dict[$_.ScsiCanonicalName]}}, state
