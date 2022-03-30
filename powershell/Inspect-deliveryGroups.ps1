#https://vmind.ru/2020/03/16/clean-distribution-group-exchange/#more-8661
$addresslist=(Get-DistributionGroup -ResultSize unlimited).emailaddresses.smtpaddress
$addresslist+=(Get-dynamicDistributionGroup -ResultSize unlimited).emailaddresses.smtpaddress
$dict=@{}
$addresslist | %{$dict[$_] = 0}

$Mailboxservers = Get-MailBoxServer | % { "http://$($_.Name)/PowerShell/" }
Invoke-Command -ConfigurationName Microsoft.Exchange -ConnectionUri $Mailboxservers -Authentication Kerberos -Script {
Get-MessageTrackingLog -EventId submit -ResultSize Unlimited |Select-Object -ExpandProperty recipients} | %{
  if($dict[$_] -ge 0){$dict[$_]++}
}

$dict.GetEnumerator() | ?{$_.value -ne 0} | select key,value | export-csv -NoTypeInformation C:\tmp\all2.csv
