# Task 4: Windows Firewall Configuration

## Overview
This repository contains the configuration and testing of Windows Firewall rules as part of Task 4 of the Elevate Cyber Security Internship. The task demonstrates basic firewall management skills and understanding of network traffic filtering.

## Objective
Configure and test basic firewall rules to allow or block specific network traffic using Windows Defender Firewall with Advanced Security.

## System Information
- *Operating System*: Windows 10/11
- *Firewall Tool*: Windows Defender Firewall with Advanced Security
- *Method Used*: GUI-based configuration with command-line testing
- *Test Date*: May 30, 2025

## Task Implementation

### Step 1: Initial Firewall Assessment
- Opened Windows Defender Firewall with Advanced Security (wf.msc)
- Documented current inbound and outbound rules
- Captured baseline firewall configuration

### Step 2: Creating Block Rule for Port 23 (Telnet)
*Rule Configuration:*
- *Rule Name*: "Block Telnet Port 23"
- *Rule Type*: Inbound Rule
- *Protocol*: TCP
- *Port*: 23 (Telnet)
- *Action*: Block the connection
- *Profiles*: Domain, Private, Public (All)

*Implementation Process:*
1. Navigated to Inbound Rules → New Rule
2. Selected Port rule type
3. Specified TCP protocol and port 23
4. Configured to block all connections
5. Applied to all network profiles for comprehensive security

### Step 3: Testing the Block Rule
*Testing Method:*
cmd
C:\Windows\System32>telnet localhost 23


*Expected Result:*
- Command failed with "'telnet' is not recognized as an internal or external command"
- This demonstrates Windows security by default (Telnet client disabled)
- Confirms that even if Telnet were enabled, port 23 would be blocked by firewall

*Alternative Testing:*
powershell
Test-NetConnection -ComputerName localhost -Port 23 -InformationLevel Detailed


### Step 4: Creating Allow Rule (Demonstration)
*Rule Configuration:*
- *Rule Name*: "Allow HTTP Port 80"
- *Rule Type*: Inbound Rule
- *Protocol*: TCP
- *Port*: 80 (HTTP)
- *Action*: Allow the connection
- *Profiles*: Domain, Private, Public

### Step 5: Rule Documentation and Verification
- Verified rules appear in Windows Firewall interface
- Confirmed rule priorities and effective policies
- Documented rule details and configurations

### Step 6: Cleanup and Restoration
- Removed test rules to restore original firewall state
- Verified firewall returned to baseline configuration
- Maintained system security posture

## Security Analysis

### Why Block Port 23 (Telnet)?
1. *Unencrypted Communication*: Telnet transmits data in plain text
2. *Credential Exposure*: Username and passwords sent without encryption
3. *Legacy Protocol*: Replaced by SSH for secure remote access
4. *Attack Vector*: Commonly targeted by malicious actors
5. *Best Practice*: Modern systems should block Telnet by default

### Firewall Traffic Filtering Mechanism
*How Windows Firewall Filters Traffic:*
1. *Packet Inspection*: Examines incoming and outgoing network packets
2. *Rule Matching*: Compares packets against configured rules
3. *Priority Processing*: Processes rules in order of priority
4. *Action Execution*: Allows, blocks, or drops packets based on matching rules
5. *Stateful Filtering*: Tracks connection states for enhanced security

### Inbound vs Outbound Rules
- *Inbound Rules*: Control traffic coming into the computer
- *Outbound Rules*: Control traffic leaving the computer
- *Default Behavior*: Windows typically blocks unsolicited inbound traffic

## Tools and Commands Used

### GUI Tools
- *Windows Defender Firewall with Advanced Security* (wf.msc)
- Control Panel → System and Security → Windows Defender Firewall

### Command Line Tools
cmd
# Testing connectivity
telnet localhost 23

# Alternative testing
Test-NetConnection -ComputerName localhost -Port 23


### PowerShell Commands (Alternative Method)
powershell
# View firewall profiles
Get-NetFirewallProfile

# Create block rule
New-NetFirewallRule -DisplayName "Block Telnet Port 23" -Direction Inbound -Protocol TCP -LocalPort 23 -Action Block

# Remove rule
Remove-NetFirewallRule -DisplayName "Block Telnet Port 23"


## Key Learning Outcomes

### Technical Skills Developed
1. *Firewall Configuration*: Hands-on experience with Windows Firewall management
2. *Network Security*: Understanding of port-based traffic filtering
3. *Security Testing*: Methods to verify firewall rule effectiveness
4. *Documentation*: Professional security configuration documentation

### Security Concepts Mastered
- *Stateful vs Stateless Firewalls*: Windows Firewall operates as stateful
- *Default Deny Policy*: Secure configuration blocks unnecessary traffic
- *Network Segmentation*: Using firewall rules for access control
- *Security Hardening*: Disabling insecure protocols and services

## Interview Preparation

### Key Questions and Answers
1. *What is a firewall?*
   - Network security device that monitors and controls network traffic based on predetermined security rules

2. *Difference between stateful and stateless firewall?*
   - Stateful tracks connection states; stateless examines packets independently

3. *What are inbound and outbound rules?*
   - Inbound: Controls incoming traffic; Outbound: Controls outgoing traffic

4. *Why block port 23 (Telnet)?*
   - Unencrypted protocol vulnerable to eavesdropping and credential theft

5. *How does a firewall improve network security?*
   - Creates security perimeter, blocks unauthorized access, prevents data exfiltration

## Repository Contents
- README.md - This documentation file
- screenshots/ - Visual documentation of firewall configuration
  - initial_firewall_state.png - Baseline firewall configuration
  - creating_block_rule.png - Process of creating block rule for port 23
  - block_rule_created.png - Confirmation of block rule creation
  - testing_blocked_connection.png - Command line test showing blocked access
  - firewall_rules_summary.png - Summary of all configured rules
  - cleanup_process.png - Removal of test rules
- commands_log.txt - Record of all commands executed
- firewall_analysis.md - Detailed technical analysis

## Security Recommendations
1. *Regular Firewall Audits*: Review and update firewall rules quarterly
2. *Principle of Least Privilege*: Only allow necessary network access
3. *Default Deny Policy*: Block all traffic except explicitly allowed
4. *Logging and Monitoring*: Enable firewall logging for security analysis
5. *Network Segmentation*: Use firewalls to isolate network segments

## Conclusion
This task successfully demonstrated fundamental firewall management skills using Windows native security tools. The configuration of block and allow rules, combined with testing procedures, provides practical experience in network security controls.

The exercise reinforced the importance of proactive security measures and proper documentation of security configurations. Understanding firewall operations is crucial for cybersecurity professionals in defending against network-based attacks.

---
*Task Completed*: May 30, 2025  
*Security Status*: All test rules removed, baseline restored  
*Next Steps*: Regular firewall monitoring and rule optimization
