$allMS = Get-SCOMManagementServer | ? {$_.IsGateway -eq $false}

foreach ($oneMS in $allMS) {
    "-"*40
    $oneMS.PrincipalName
    if ($oneMS.ComputerName -eq (hostname)) {
        $Cert = (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Machine Settings").ChannelCertificateHash
        if ($Cert) {
            write-host -ForegroundColor Green "Certificate registered :" $Cert
        } else {
            write-host -ForegroundColor Red "Certificate missing."
        }
    } else {
        Invoke-Command -ComputerName $oneMS.PrincipalName {
            $Cert = (Get-ItemProperty "HKLM:SOFTWARE\Microsoft\Microsoft Operations Manager\3.0\Machine Settings").ChannelCertificateHash
            if ($Cert) {
                write-host -ForegroundColor Green "Certificate registered :" $Cert
            } else {
                write-host -ForegroundColor Red "Certificate missing."
            }
        }
    }
}
