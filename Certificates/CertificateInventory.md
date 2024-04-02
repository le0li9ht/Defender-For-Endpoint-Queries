This page offers queries for accessing certificate inventory details from Microsoft 365 Defender using KQL  
### Introduction
The Certificate inventory lets you view a list of the certificates installed across your organization in a single central certificate inventory page. This can help you:
* Identify certificates that are about to expire so you can update them and prevent service disruption
* Detect potential vulnerabilities due to the use of weak signature algorithm (e.g. SHA-1-RSA), short key size (e.g. RSA 512bit), or weak signature hash algorithm (e.g. MD5)
* Ensure compliance with regulatory guidelines and organizational policy

![image](https://github.com/le0li9ht/Defender-For-Endpoint-Queries/assets/34128579/0eb4df5f-680c-4cb0-93cb-fc881447dc43)

### Queries
Retrieve the list of certificates that are going to expire soon  

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
Retrieve the certificates with smaller key sizes  
```
//Certificates that don't have 2048-bit keysize
let dict1=DeviceInfo
| where Timestamp >ago(90d)
| summarize arg_max(Timestamp, *) by DeviceName
| summarize count() by DeviceId, DeviceName
| extend dict2=bag_pack(DeviceId, DeviceName)
| summarize dict1=make_bag(dict2)
| project dict1;
DeviceTvmCertificateInfo
| where KeySize in (512,1024,1536)
| summarize InstalledDevices=array_length(make_set(DeviceId)),Instances=count() by Thumbprint
| join (DeviceTvmCertificateInfo
| summarize arg_max(Thumbprint,*) by Thumbprint
| where KeySize in (512,1024,1536)
| extend DeviceName=toscalar(dict1)[DeviceId]
| project DeviceName,IssuedTo=tostring(IssuedTo["CommonName"]),IssuedBy=tostring(IssuedBy.["CommonName"]),KeySize, SignatureAlgorithm, IssueDate, ExpirationDate,Thumbprint,Path, ExtendedKeyUsage, SerialNumber
) on Thumbprint
| project-reorder Thumbprint, DeviceName, InstalledDevices
```
Retrieve certificates with weak signature algorithms.  
```
//Certificates with weak signature hash algorithm.
let dict1=DeviceInfo
| where Timestamp >ago(90d)
| summarize arg_max(Timestamp, *) by DeviceName
| summarize count() by DeviceId, DeviceName
| extend dict2=bag_pack(DeviceId, DeviceName)
| summarize dict1=make_bag(dict2)
| project dict1;
DeviceTvmCertificateInfo
| where SignatureAlgorithm  in ("md5RSA","sha1RSA","sha1DSA")
| summarize InstalledDevices=array_length(make_set(DeviceId)),Instances=count() by Thumbprint
| join (DeviceTvmCertificateInfo
| summarize arg_max(Thumbprint,*) by Thumbprint
| where SignatureAlgorithm  in ("md5RSA","sha1RSA","sha1DSA")
| extend DeviceName=toscalar(dict1)[DeviceId]
| project DeviceName,IssuedTo=tostring(IssuedTo["CommonName"]),IssuedBy=tostring(IssuedBy.["CommonName"]),KeySize, SignatureAlgorithm, IssueDate, ExpirationDate,Thumbprint,Path, ExtendedKeyUsage, SerialNumber
) on Thumbprint
| project-reorder Thumbprint, DeviceName, InstalledDevices
```
Expired Certificates List   
```
//Expired Certificates List
let dict1=DeviceInfo
| where Timestamp >ago(90d)
| summarize arg_max(Timestamp, *) by DeviceName
| summarize count() by DeviceId, DeviceName
| extend dict2=bag_pack(DeviceId, DeviceName)
| summarize dict1=make_bag(dict2)
| project dict1;
DeviceTvmCertificateInfo
| where ExpirationDate<=now()
| summarize InstalledDevices=array_length(make_set(DeviceId)),Instances=count() by Thumbprint
| join (DeviceTvmCertificateInfo  | summarize arg_max(Thumbprint,*) by Thumbprint | where ExpirationDate<=now()
| extend DeviceName=toscalar(dict1)[DeviceId]
| project DeviceName,IssuedTo=tostring(IssuedTo["CommonName"]),IssuedBy=tostring(IssuedBy.["CommonName"]),KeySize, SignatureAlgorithm, IssueDate, ExpirationDate,Thumbprint,Path, ExtendedKeyUsage, SerialNumber
) on Thumbprint
| project-reorder Thumbprint, DeviceName, InstalledDevices
```
