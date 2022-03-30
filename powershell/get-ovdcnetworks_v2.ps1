#Script makes an Excel file, which contains oVDC's networks. It takes VCD list from vcd_list.txt file.
function Get-Netmask {
  param ($prefixLength)
  $bitString = ('1' * $prefixLength).PadRight(32, '0')
  $ipString=[String]::Empty

# make 1 string combining a string for each byte and convert to int
  for($i=0;$i -lt 32;$i+=8){
    $byteString=$bitString.Substring($i,8)
    $ipString+="$([Convert]::ToInt32($byteString, 2))."
  }
  $ipString.TrimEnd('.')
}

$ExcelApplication = new-object -comobject excel.application 
$ExcelApplication.Visible = $false
$WorkBook = $ExcelApplication.Workbooks.Add()
$sheets = 1

$apiVersion = '35.0'
$cred = Get-Credential
$password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password))
if($password -like "*:*"){Write-Host("Password is containing ':'. Exiting now...");break}
$userPass = $cred.Username
if(!($userPass -like "*@*")){$userPass += "@system"}
$userPass += ":$password"
$bytes= [System.Text.Encoding]::UTF8.GetBytes($userpass)
$encodedlogin=[Convert]::ToBase64String($bytes)

$content = get-content vcd_list.txt | sort -Descending

foreach ($cont in $content) {
  $base_uri = $cont
  $sheets += 1
  $xws1 = $WorkBook.Worksheets.add()
  $xws1.Name = $base_uri.split('/')[2]
  $headers = @{}
  $authheader = "Basic " + $encodedlogin
  $headers.Add("Authorization",$authheader)

  $version_uri = $base_uri + "api/versions"
  try {$get_version = Invoke-RestMethod -Uri $version_uri -Headers $headers -Method GET -ErrorAction Stop}
  catch {$err_mes = $_;$get_version = $false}

  $check_version = $get_version.SupportedVersions.VersionInfo | Where-Object {$_.Version -eq $apiVersion} 

  if ($check_version){
    $headers.Add("Accept","application/*;version=$apiVersion")
    $session_uri = $base_uri + "api/sessions"
    try{$get_session = Invoke-WebRequest -Uri $session_uri -Headers $headers -Method POST -ErrorAction Stop}
    catch{$err_mes = $_;$get_version = $false}
    if ($get_session.StatusCode -eq '200'){
      $base_uri
      Write-Host "Success" -ForegroundColor White
      $bearer_token = 'Bearer '+ $get_session.Headers.Item('X-VMWARE-VCLOUD-ACCESS-TOKEN')
      $headers.Remove("Authorization")
      $headers.Add("Authorization",$bearer_token)
      $net_uri = $base_uri + 'cloudapi/1.0.0/orgVdcNetworks'
      $Data = Invoke-RestMethod -Uri $net_uri -Headers $headers -Method get -ContentType 'application/*+json'
      $total = $Data.resultTotal
      for ($num = 1 ; $num -le [int][Math]::Ceiling($total / 16) ; $num++){
        $tmp_net_uri = $net_uri + '?page=' + [string]$num + '&pageSize=16'
        $Data = Invoke-RestMethod -Uri $tmp_net_uri -Headers $headers -Method get -ContentType 'application/*+json'
        if($num -eq 1){$orgnets = $Data.values}
        else{$orgnets += $Data.values}
        }
      $orgVDCs = @()
      for ($num = 0 ; $num -lt $total ; $num++){
        $row = "" | select Tenant, vDC, OrgVdcNetwork, Gateway, Netmask
        $row.Tenant = $orgnets[$num].orgref.name
        $row.vDC = $orgnets[$num].orgvdc.name
        $row.OrgVdcNetwork = $orgnets[$num].name
        $tmp_net_uri = $net_uri + '/' + $orgnets[$num].id
        $Data = Invoke-RestMethod -Uri $tmp_net_uri -Headers $headers -Method get -ContentType 'application/*+json'
        $row.Gateway = $Data.subnets.values.gateway
        $row.Netmask = Get-Netmask -prefixLength $Data.subnets.values.prefixlength
        $orgVDCs += $row
        }
      $orgVDCs_tmp = $orgVDCs | sort Tenant
      $xws1.Cells.Item(1,1) = 'Tenant'
      $xws1.Cells.Item(1,2) = 'vDC'
      $xws1.Cells.Item(1,3) = 'OrgVdcNetwork'
      $xws1.Cells.Item(1,4) = 'Gateway'
      $xws1.Cells.Item(1,5) = 'Netmask'
      for ($num = 0 ; $num -lt $total ; $num++){
        $xws1.Cells.Item($num+2,1) = $orgVDCs_tmp[$num].Tenant
        $xws1.Cells.Item($num+2,2) = $orgVDCs_tmp[$num].vDC
        $xws1.Cells.Item($num+2,3) = $orgVDCs_tmp[$num].OrgVdcNetwork
        $xws1.Cells.Item($num+2,4) = $orgVDCs_tmp[$num].Gateway
        $xws1.Cells.Item($num+2,5) = $orgVDCs_tmp[$num].Netmask
        }    
      $usedRange = $xws1.UsedRange
      $usedRange.EntireColumn.AutoFit() | Out-Null
      }
    else{Write-Host "Failed" -ForegroundColor Red;Write-Host $err_mes.Exception -ForegroundColor Red}
  }
  else{Write-Host "Failed" -ForegroundColor Red;Write-Host $err_mes.Exception -ForegroundColor Red}
}
$ext=".xlsx"
$path=(Get-Location).Path + "\orgvdcnet$ext"
$ExcelApplication.DisplayAlerts = $false;
$workbook.Worksheets.Item($sheets).Delete()
$WorkBook.Saveas($path)
$WorkBook.Close()
$ExcelApplication.Quit()
