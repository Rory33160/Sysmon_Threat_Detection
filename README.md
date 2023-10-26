# Sysmon_Threat_Detection
This is  the Try Hack Me sysmon room walk through , using sysmon and Powershell for detecting threats on endpoints

Sysmon Endpoint Threat detection

Tools used:
Sysmon, Powershell and Event Viewer

Investigation 1 - ugh, BILL THAT'S THE WRONG USB!

In this investigation, your team has received reports that a malicious file was dropped onto a host by a malicious USB. They have pulled the logs suspected and have tasked you with running the investigation for it.


What is the full registry key of the USB device calling svchost.exe in Investigation 1?

![image](https://github.com/Rory33160/Sysmon_Threat_Detection/assets/47018034/58d14f19-2a26-44a9-a8a8-21b1cb4896db)

The answer is found in in event viewer, event 13 :
HKLM\System\CurrentControlSet\Enum\WpdBusEnumRoot\UMB\2&37c186b&0&STORAGE#VOLUME#_??_USBSTOR#DISK&VEN_SANDISK&PROD_U3_CRUZER_MICRO&REV_8.01#4054910EF19005B3&0#\FriendlyName
TargetObject: U
Details: %8

![image](https://github.com/Rory33160/Sysmon_Threat_Detection/assets/47018034/1427bf52-95e0-4909-b3e3-d9653402950d)

What is the device name when being called by RawAccessRead in Investigation 1?
Filtering for “rawaccessread” and event ID 9

\Device\HarddiskVolume3

![image](https://github.com/Rory33160/Sysmon_Threat_Detection/assets/47018034/e42fd054-675e-4969-a0f0-5221db6e2a1e)


What is the first exe the process executes in Investigation 1?
 Looking through event viewer from the earliest date.

rundll32.exe

![image](https://github.com/Rory33160/Sysmon_Threat_Detection/assets/47018034/5bb1409d-e1fb-4f91-9997-2163ac02784a)

What is the full path of the payload in Investigation 2?

There is only 3 log items so no filtering required. This full path is in the earliest log.

C:\Windows\System32\mshta.exe" "C:\Users\IEUser\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\S97WTYG7\update.hta

![image](https://github.com/Rory33160/Sysmon_Threat_Detection/assets/47018034/297ab595-6df3-4e2d-bab7-b9490312bcde)

What signed binary executed the payload in Investigation 2?

C:\Users\IEUser\Downloads\update.html

![image](https://github.com/Rory33160/Sysmon_Threat_Detection/assets/47018034/7cdfbe90-9e83-4a17-bdff-5d31c148856f)


What signed binary executed the payload in Investigation 2?
C:\Windows\System32\mshta.exe

![image](https://github.com/Rory33160/Sysmon_Threat_Detection/assets/47018034/6246660b-8669-4867-8a67-08131ce1d26c)


What is the IP of the adversary in Investigation 2?

10.0.2.18

![image](https://github.com/Rory33160/Sysmon_Threat_Detection/assets/47018034/1d89fd83-b3bd-4008-bbba-ac26470fcc9b)

What back connect port is used in Investigation 2?

DestinationPort: 4443
For investigation 3.1 and 3.2, we can bring up the logs in PowerShell with the following path.

![image](https://github.com/Rory33160/Sysmon_Threat_Detection/assets/47018034/71af9ae6-42c4-43fc-8eea-949ce2a9a06f)

Event ID 3 with network connection answers the next 3 questions 

What is the IP of the suspected adversary in Investigation 3.1?
172.30.1.253

What is the hostname of the affected endpoint in Investigation 3.1?

DESKTOP-O153T4R


What is the hostname of the C2 server connecting to the endpoint in Investigation 3.1?
empirec2

![image](https://github.com/Rory33160/Sysmon_Threat_Detection/assets/47018034/f9d5825d-841d-4cab-8049-80ac40a045a2)

Where in the registry was the payload stored in Investigation 3.1?
HKLM\SOFTWARE\Microsoft\Network\debug

![image](https://github.com/Rory33160/Sysmon_Threat_Detection/assets/47018034/94b859c1-1c35-4413-b497-b203ca6ca5c9)

What PowerShell launch code was used to launch the payload in Investigation 3.1?
Found in event ID 13 

![image](https://github.com/Rory33160/Sysmon_Threat_Detection/assets/47018034/d29b14b7-b8ca-433a-8acd-5a5671adae8c)

What is the IP of the adversary in Investigation 3.2?

172.168.103.188

![image](https://github.com/Rory33160/Sysmon_Threat_Detection/assets/47018034/9f4d8177-8be2-4d73-9315-f45bc353a27f)


What is the full path of the payload location in Investigation 3.2?

c:\users\q\AppData:blah.txt

![image](https://github.com/Rory33160/Sysmon_Threat_Detection/assets/47018034/7ba0e986-bac4-4edd-a904-875548e9dbb3)

What was the full command used to create the scheduled task in Investigation 3.2?
C:\WINDOWS\system32\schtasks.exe" /Create /F /SC DAILY /ST 09:00 /TN Updater /TR "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c \"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String($(cmd /c ''more < c:\users\q\AppData:blah.txt'''))))\""</

![image](https://github.com/Rory33160/Sysmon_Threat_Detection/assets/47018034/a823402c-3ec2-4534-8f48-7f2f1685dd82)

What process was accessed by schtasks.exe that would be considered suspicious behavior in Investigation 3.2?

Lsass.exe

![image](https://github.com/Rory33160/Sysmon_Threat_Detection/assets/47018034/089650cd-6bc9-463a-845c-c316866d566c)

Event ID 3 , the earliest connection answer the next two questions


What is the IP of the adversary in Investigation 4?

172.30.1.253

What port is the adversary operating on in Investigation 4?

80

![image](https://github.com/Rory33160/Sysmon_Threat_Detection/assets/47018034/d3b0a540-9b11-47d1-afbd-ceb89ac8de4b)















