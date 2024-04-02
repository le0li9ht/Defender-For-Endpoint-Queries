The Certificate inventory lets you view a list of the certificates installed across your organization in a single central certificate inventory page. This can help you:
* Identify certificates that are about to expire so you can update them and prevent service disruption
* Detect potential vulnerabilities due to the use of weak signature algorithm (e.g. SHA-1-RSA), short key size (e.g. RSA 512bit), or weak signature hash algorithm (e.g. MD5)
* Ensure compliance with regulatory guidelines and organizational policy

```
//Certificates Going To Expire Soon(Certificates that will expire in 90 days or less)
let dict1=DeviceInfo
| where Timestamp >ago(90d)
| summarize arg_max(Timestamp, *) by DeviceName
| summarize count() by DeviceId, DeviceName
| extend dict2=bag_pack(DeviceId, DeviceName)
| summarize dict1=make_bag(dict2)
| project dict1;
DeviceTvmCertificateInfo
| extend days=datetime_diff('day',ExpirationDate,now())
| where days>0 and days<=90
| summarize InstalledDevices=array_length(make_set(DeviceId)),Instances=count() by Thumbprint
| join (DeviceTvmCertificateInfo
| summarize arg_max(Thumbprint,*) by Thumbprint
| extend days=datetime_diff('day',ExpirationDate,now())
| where days>0 and days<=90
| extend DeviceName=toscalar(dict1)[DeviceId]
| project DeviceName,IssuedTo=tostring(IssuedTo["CommonName"]),IssuedBy=tostring(IssuedBy.["CommonName"]),KeySize, SignatureAlgorithm, IssueDate, ExpirationDate,Thumbprint,Path, ExtendedKeyUsage, SerialNumber
) on Thumbprint
| project-reorder Thumbprint, DeviceName, InstalledDevices
```
