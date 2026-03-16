
# 🚨 Incident Response: Brute Force Attempt Detection


---

## Scenario
As a security analyst for an organization, I observed multiple failed authentication attempts across several virtual machines in our environment. The activity suggested a possible brute force attack from multiple external IPs. 

My goal is to investigate, detect, and mitigate this potential threat in compliance with **NIST 800-61** guidelines.

---

## 🛠️ **Platforms and Tools**
- **Microsoft Sentinel**
- **Microsoft Defender for Endpoint**
- **Kusto Query Language (KQL)**
- **Windows 10 Virtual Machines (Microsoft Azure)**

---

## 🔍 **Objective: Find Brute Force and Create Sentinel Scheduled Query Rule**
Implement a **Sentinel Scheduled Query Rule** using KQL in Log Analytics to detect when the same remote IP address fails to log in to the same Azure VM 50+ times within a 5-hour period.

NOTE: This project was done in the [Cyber Range](http://joshmadakor.tech/cyber-range) which simulates an enterprise environment.
---

### **Step 1: Design Query** 

I designed a Sentinel Scheduled Query Rule within Log Analytics that will discover when the same IP address has failed to login to the same local host (Azure VM) 50 or more times within the last 5 hours.

**Detection Query:**

```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >= 50
```
![image](https://github.com/JDanielRod/Incident-Response-Scenario1/blob/main/Screenshot%202026-03-15%20155725.png)

---
### **Step 2: Create Alert Rule**

Next, I created a Schedule Query Rule in Sentinel. I used the detection query from above.

![image](https://github.com/JDanielRod/Incident-Response-Scenario1/blob/main/image.png)

---

### **Step 3: Incident is created**

After creating the Scheduled Query Rule, an incident was created, which I assigned to myself and set the status to active, as I began to work through it.

![image](https://github.com/JDanielRod/Incident-Response-Scenario1/blob/main/IncidentAssign.png)

---

## 🚨 **Incident Response Phases**
### 1️⃣ Preparation
1. **Policies and Procedures:**
   - Establish protocols for handling brute-force attempts, account lockouts, and account recovery.
   - Include predefined actions for notifications, account lockdowns, and reporting suspicious activity.

2. **Access Control and Logging:**
   - Enable logging of all login attempts across Azure AD.
   - Integrate with **Microsoft Defender for Identity** and **Azure Sentinel** for automated detection and alerts.

3. **Training:**
   - Train the security team to handle credential-based attacks, including brute force and credential stuffing.

4. **Communication Plan:**
   - Create an escalation plan for IT support and privileged account holders during incidents.

---

### 2️⃣ Detection & Analysis
#### Observations:

From my query, I observed 4 different vms were potentially impacted by brute force attempts from 5 different public ips on internet. 

![image](https://github.com/JDanielRod/Incident-Response-Scenario1/blob/main/Investigation.png)


| Remote IP       | Action Type | Device Name                                                                 | Failed Attempts |
|-----------------|-------------|------------------------------------------------------------------------------|-----------------|
| 80.94.95.238    | LogonFailed | yves-windows11                                                              | 56              |
| 209.38.80.147   | LogonFailed | levi-linux-test-vm.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net      | 57              |
| 209.38.22.111   | LogonFailed | levi-linux-test-vm.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net      | 53              |
| 185.156.73.169  | LogonFailed | vm-final-lab-tk                                                             | 300             |
| 185.156.73.169  | LogonFailed | shemar-endpoint                                                             | 100             |

---

I observed the logs further to see if there were any successful logins from the IPs in question.
   - Successful Login Detection Query:
      
  ```kql
  DeviceLogonEvents
| where RemoteIP in ("80.94.95.238", "209.38.80.147", "209.38.22.111", "185.156.73.169", "185.156.73.169")
| where ActionType != "LogonFailed"
  ```
![image](https://github.com/JDanielRod/Incident-Response-Scenario1/blob/main/NoResults.png)

  **Result:** No successful logins from these IPs were detected.

---

### 3️⃣ Containment
#### Immediate Actions:
1. **Device Isolation:**
   - Isolated affected devices using **Microsoft Defender for Endpoint**.

2. **Network Security Group (NSG) Update:**
   - Restricted RDP access to authorized IPs only.
   - Blocked all external IPs linked to failed login attempts.

3. **Anti-Malware Scans:**
   - Performed scans on affected devices for potential compromise.

---

### 4️⃣ Eradication & Recovery
1. **Password Reset:**
   - Reset passwords for targeted accounts.
   - Enforced strong password policies for privileged accounts.

2. **MFA Enforcement:**
   - Enabled multi-factor authentication for all high-value accounts.

3. **Geo-blocking:**
   - Blocked login attempts from high-risk geolocations.

---

### 5️⃣ Post-Incident Activity
1. **Lessons Learned:**
   - Was detection quick and effective?
   - Were privileged accounts adequately protected?

2. **System Improvements:**
   - Adjusted login thresholds for quicker detection.
   - Expanded employee training on password security.

3. **Documentation:**
   - Recorded all findings, actions taken, and future recommendations.
---

## Incident Closure

   -Brute force attempts were not successful as the query for successful logins yieleded no results.
   -I closed the incident as a **"True Positive"**. 
   -I placed my notes of the incident in the acitivity log.

![image](https://github.com/JDanielRod/Incident-Response-Scenario1/blob/main/IncidentClosing.png)
