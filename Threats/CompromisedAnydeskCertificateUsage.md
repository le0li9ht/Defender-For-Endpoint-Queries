
### Compromised Anydesk Certificate Usage  

```
//Find the presence of anydesk software with compromised signing certs
DeviceFileCertificateInfo
| where Timestamp >ago(90d)
| where CertificateSerialNumber =~ "0dbf152deaf0b981a8a938d53f769db8"
| where Issuer=~"DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
| where Signer !~ "Anydesk Software GmbH"
```
```
//Find whether the anydesk process was run.
DeviceFileCertificateInfo
| where Timestamp >ago(90d)
| where CertificateSerialNumber =~ "0dbf152deaf0b981a8a938d53f769db8"
| where Issuer=~"DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
| where Signer !~ "Anydesk Software GmbH"
| join kind=rightsemi (DeviceProcessEvents) on SHA1
```
```
//Find the versions of those anydesk software.
DeviceFileCertificateInfo
| where Timestamp >ago(90d)
| where CertificateSerialNumber =~ "0dbf152deaf0b981a8a938d53f769db8" or CertificateSerialNumber=~"08AD40B260D29C4C9F5ECDA9BD93AED9"
| where Issuer contains "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
//| where Signer !~ "Anydesk Software GmbH"
| summarize count() by DeviceName
| join kind=rightsemi (DeviceTvmSoftwareInventory | where SoftwareName contains "Anydesk") on DeviceName
```
References:
* https://anydesk.com/en/public-statement
* https://github.com/Neo23x0/signature-base/blob/master/yara/gen_anydesk_compromised_cert_feb23.yar
* https://support.anydesk.com/knowledge/how-do-i-make-sure-i-use-anydesk-with-the-new-certificate
* https://www.virustotal.com/gui/file/ac71f9ab4ccb920a493508b0e0577b31fe547aa07e914f58f1def47d08ebcf7d/details
