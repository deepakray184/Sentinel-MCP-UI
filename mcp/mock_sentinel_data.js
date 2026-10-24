// Realistic Microsoft Sentinel Security Incidents and Telemetry
// Mirroring Microsoft Sentinel, Microsoft Defender XDR & Entra ID Protection

const mockIncidents = [
  {
    id: "INC-8042",
    incidentNumber: 8042,
    title: "Multi-Stage Ransomware Attack & Shadow Copy Deletion on SQL Database",
    severity: "High",
    status: "Active",
    classification: "TruePositive",
    classificationReason: "SuspiciousActivity",
    createdTimeUtc: "2026-10-24T18:12:00Z",
    lastModifiedTimeUtc: "2026-10-24T22:30:00Z",
    assignedTo: "SecOps Tier 3 (Daniel S.)",
    tactics: ["InitialAccess", "Execution", "DefenseEvasion", "LateralMovement", "Impact"],
    techniques: ["T1059.001", "T1003.001", "T1490", "T1486", "T1021.002"],
    description: "Sentinel detected multi-stage lateral movement originating from finance workstation WKS-FIN-882 to production database SRV-FIN-SQL01. Adversaries utilized stolen credentials to execute encoded PowerShell, dump LSASS credentials, delete Volume Shadow Copies via vssadmin, and initiate bulk file encryption matching BlackCat/ALPHV ransomware signatures.",
    summary: "Active ransomware deployment in progress against financial database tier. Host isolation and credential revocation executed. Encrypted files identified in 3 network shares.",
    metrics: {
      riskScore: 94,
      confidenceScore: 98,
      blastRadius: "High (3 endpoints, 1 database cluster)",
      potentialDataLoss: "High"
    },
    entities: [
      {
        type: "Account",
        name: "finance-admin@contoso.com",
        properties: {
          accountName: "finance-admin",
          userPrincipalName: "finance-admin@contoso.com",
          aadUserId: "8b7a42e1-9f93-4a2a-b94d-1149fecba129",
          riskLevel: "High",
          isDomainAdmin: true,
          mfaEnrolled: true,
          lastSeenIp: "185.220.101.5"
        }
      },
      {
        type: "Host",
        name: "SRV-FIN-SQL01",
        properties: {
          dnsHostName: "SRV-FIN-SQL01.contoso.local",
          netBiosName: "SRV-FIN-SQL01",
          osFamily: "WindowsServer",
          osVersion: "Windows Server 2022 Datacenter",
          ipAddress: "10.0.4.15",
          defenderStatus: "Active",
          isolationStatus: "Not Isolated"
        }
      },
      {
        type: "Host",
        name: "WKS-FIN-882",
        properties: {
          dnsHostName: "WKS-FIN-882.contoso.local",
          netBiosName: "WKS-FIN-882",
          osFamily: "Windows",
          osVersion: "Windows 11 Enterprise 23H2",
          ipAddress: "10.0.4.42",
          defenderStatus: "Active",
          isolationStatus: "Isolated"
        }
      },
      {
        type: "IP",
        name: "185.220.101.5",
        properties: {
          address: "185.220.101.5",
          country: "Seychelles (Tor Exit Node)",
          asn: "AS60729",
          threatReputation: "Known C2 / Cobalt Strike / BlackCat Ransomware affiliate",
          threatScore: 99
        }
      },
      {
        type: "FileHash",
        name: "enc_locker.exe (SHA256)",
        properties: {
          fileName: "enc_locker.exe",
          sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          threatFamily: "Win32/BlackCat.Ransomware!MSR",
          filePath: "C:\\ProgramData\\UpdateMgr\\enc_locker.exe"
        }
      },
      {
        type: "AzureResource",
        name: "/subscriptions/sub-corp-01/resourceGroups/rg-fin-prod/providers/Microsoft.Compute/virtualMachines/SRV-FIN-SQL01",
        properties: {
          resourceType: "Virtual Machine",
          location: "eastus2",
          backupProtected: true
        }
      }
    ],
    alerts: [
      {
        alertId: "ALT-99101",
        alertDisplayName: "Suspicious Encoded PowerShell Command Execution",
        severity: "High",
        provider: "Microsoft Defender for Endpoint",
        timeGenerated: "2026-10-24T18:12:15Z",
        description: "PowerShell.exe executed with -EncodedCommand downloading remote payload from 185.220.101.5 into C:\\ProgramData\\UpdateMgr\\",
        tactics: ["Execution", "DefenseEvasion"]
      },
      {
        alertId: "ALT-99102",
        alertDisplayName: "LSASS Memory Read for Credential Theft",
        severity: "High",
        provider: "Microsoft Defender for Endpoint",
        timeGenerated: "2026-10-24T18:18:40Z",
        description: "Process rundll32.exe injected into lsass.exe to dump Kerberos ticket hashes",
        tactics: ["CredentialAccess"]
      },
      {
        alertId: "ALT-99103",
        alertDisplayName: "Inhibit System Recovery: Volume Shadow Copies Deleted",
        severity: "High",
        provider: "Microsoft Sentinel Analytics",
        timeGenerated: "2026-10-24T18:24:02Z",
        description: "Command line detected: 'vssadmin.exe delete shadows /all /quiet' followed by 'wbadmin delete catalog -quiet'",
        tactics: ["DefenseEvasion", "Impact"]
      },
      {
        alertId: "ALT-99104",
        alertDisplayName: "Rapid File Renaming & Encryption Activity on Multiple Shares",
        severity: "Critical",
        provider: "Microsoft Defender for Identity",
        timeGenerated: "2026-10-24T18:31:10Z",
        description: "Over 4,200 files appended with .locked extension across financial network drives \\\\SRV-FIN-SQL01\\Accounting",
        tactics: ["Impact"]
      }
    ],
    timeline: [
      {
        time: "18:05 UTC",
        tactic: "Initial Access",
        phase: "Phishing / Credential Reuse",
        details: "Compromised credential of finance-admin@contoso.com used to authenticate via RDP onto WKS-FIN-882 from external VPN."
      },
      {
        time: "18:12 UTC",
        tactic: "Execution",
        phase: "Staging Payload",
        details: "Encoded PowerShell executed; staged C2 downloader script fetching enc_locker.exe payload."
      },
      {
        time: "18:18 UTC",
        tactic: "Credential Access",
        phase: "LSASS Memory Dump",
        details: "Adversary ran memory dump against LSASS, obtaining domain service credentials."
      },
      {
        time: "18:22 UTC",
        tactic: "Lateral Movement",
        phase: "SMB Pivot to SQL Cluster",
        details: "Adversary connected to SRV-FIN-SQL01 via PsExec/SMB admin shares (C$) with stolen admin tokens."
      },
      {
        time: "18:24 UTC",
        tactic: "Defense Evasion",
        phase: "VSS Destruction",
        details: "vssadmin.exe used to purge Volume Shadow Copies, preventing local volume recovery."
      },
      {
        time: "18:31 UTC",
        tactic: "Impact",
        phase: "Mass Encryption",
        details: "BlackCat ransomware payload activated, encrypting SQL data directories and dropping README_RESTORE_DATA.txt."
      }
    ],
    remediationPlaybooks: [
      {
        playbookId: "PB-ISOLATE-HOST",
        name: "Isolate Endpoint via Defender XDR",
        target: "SRV-FIN-SQL01",
        status: "Pending",
        description: "Isolates the VM from the network while preserving Microsoft Defender telemetry & forensic access."
      },
      {
        playbookId: "PB-REVOKE-SESSION",
        name: "Revoke Entra ID Tokens & Reset Password",
        target: "finance-admin@contoso.com",
        status: "Completed",
        description: "Invalidates all active refresh tokens, kicks active browser sessions, and marks user as High Risk in Entra ID."
      },
      {
        playbookId: "PB-BLOCK-C2-IP",
        name: "Push IP Block Rule to Azure Firewall & NSG",
        target: "185.220.101.5",
        status: "Completed",
        description: "Adds global drop rule across edge firewall and Azure virtual network security groups."
      },
      {
        playbookId: "PB-SNAPSHOT-RESTORE",
        name: "Initiate Azure Backup Vault Point-in-Time Restore",
        target: "rg-fin-prod/SRV-FIN-SQL01",
        status: "Ready",
        description: "Mounts immutable recovery point snapshot taken 2 hours before the ransomware detonation."
      }
    ]
  },
  {
    id: "INC-7391",
    incidentNumber: 7391,
    title: "Impossible Travel & Session Cookie Hijacking on Entra ID Global Admin",
    severity: "High",
    status: "Active",
    classification: "TruePositive",
    classificationReason: "SuspiciousActivity",
    createdTimeUtc: "2026-10-24T14:40:00Z",
    lastModifiedTimeUtc: "2026-10-24T16:15:00Z",
    assignedTo: "SecOps Tier 2 (Elena R.)",
    tactics: ["InitialAccess", "CredentialAccess", "Collection", "Exfiltration"],
    techniques: ["T1078.004", "T1539", "T1114.003"],
    description: "Microsoft Entra ID Protection alerted on impossible travel: user authenticated successfully from Seattle, WA, USA, and 12 minutes later established an authenticated session from Frankfurt, Germany without prompting for MFA. Investigation indicates session cookie hijacking via Adversary-in-the-Middle (AiTM) phishing proxy.",
    summary: "High-privilege Entra account compromised via Evilginx2 reverse proxy session theft. Exchange mailbox forwarding rule created to route sensitive executive emails.",
    metrics: {
      riskScore: 88,
      confidenceScore: 95,
      blastRadius: "Medium (1 Global Admin Account, Executive Mailbox)",
      potentialDataLoss: "Medium"
    },
    entities: [
      {
        type: "Account",
        name: "sarah.jenkins@contoso.com",
        properties: {
          accountName: "sarah.jenkins",
          userPrincipalName: "sarah.jenkins@contoso.com",
          aadUserId: "4f3b8901-7c22-48a1-a6e5-4089cbbda831",
          riskLevel: "High",
          role: "Global Administrator",
          department: "Human Resources / Executive Board"
        }
      },
      {
        type: "IP",
        name: "194.26.29.112",
        properties: {
          address: "194.26.29.112",
          country: "Frankfurt, Germany",
          asn: "AS209605 (HostRoyale Hosting)",
          threatReputation: "AiTM Reverse Proxy Server (Evilginx2)",
          threatScore: 92
        }
      },
      {
        type: "IP",
        name: "209.141.52.88",
        properties: {
          address: "209.141.52.88",
          country: "Seattle, WA, United States",
          asn: "AS7018 (AT&T Services)",
          threatReputation: "Legitimate Corporate VPN IP",
          threatScore: 0
        }
      },
      {
        type: "AzureResource",
        name: "Exchange Online / sarah.jenkins@contoso.com/InboxRules",
        properties: {
          resourceType: "Exchange Online Mailbox",
          ruleName: "ForwardToPersonalExternal",
          forwardTo: "sarah.jenkins.temp@protonmail.com"
        }
      }
    ],
    alerts: [
      {
        alertId: "ALT-88310",
        alertDisplayName: "Atypical Travel Detected (Seattle to Frankfurt in 12m)",
        severity: "High",
        provider: "Microsoft Entra ID Protection",
        timeGenerated: "2026-10-24T14:40:05Z",
        description: "Calculated velocity requires speed exceeding 24,000 km/h between login locations",
        tactics: ["InitialAccess"]
      },
      {
        alertId: "ALT-88311",
        alertDisplayName: "Suspicious Token Refresh from Anonymous ASN",
        severity: "High",
        provider: "Microsoft Defender for Cloud Apps",
        timeGenerated: "2026-10-24T14:42:19Z",
        description: "ESTSAuth session cookie reused with modified client TLS fingerprint",
        tactics: ["CredentialAccess"]
      },
      {
        alertId: "ALT-88312",
        alertDisplayName: "New Suspicious Inbox Forwarding Rule Added",
        severity: "Medium",
        provider: "Microsoft Sentinel Analytics",
        timeGenerated: "2026-10-24T14:45:00Z",
        description: "Inbox rule created with action 'RedirectTo' and condition matching keywords 'invoice', 'confidential', 'merger'",
        tactics: ["Collection", "Exfiltration"]
      }
    ],
    timeline: [
      {
        time: "14:28 UTC",
        tactic: "Initial Access",
        phase: "AiTM Phishing Lure",
        details: "User received email with spoofed DocuSign document link pointing to fake login portal."
      },
      {
        time: "14:32 UTC",
        tactic: "Credential Access",
        phase: "Token Interception",
        details: "AiTM proxy captured user session cookie and FIDO2 authentication response in real-time."
      },
      {
        time: "14:40 UTC",
        tactic: "Defense Evasion",
        phase: "Session Playback",
        details: "Attacker imported valid session cookie into browser in Germany, bypassing MFA check."
      },
      {
        time: "14:45 UTC",
        tactic: "Exfiltration",
        phase: "Mailbox Exfiltration Rule",
        details: "Attacker accessed Outlook Web Access and set up automated forwarding rule to external mailbox."
      }
    ],
    remediationPlaybooks: [
      {
        playbookId: "PB-DISABLE-MAIL-RULE",
        name: "Remove Malicious Exchange Inbox Rule",
        target: "sarah.jenkins@contoso.com",
        status: "Pending",
        description: "Permanently deletes the malicious mailbox redirect rule and restores default audit logs."
      },
      {
        playbookId: "PB-REVOKE-SESSION",
        name: "Revoke Entra ID Sessions & Require Password Reset",
        target: "sarah.jenkins@contoso.com",
        status: "Completed",
        description: "Revokes refresh tokens and triggers conditional access re-evaluation."
      },
      {
        playbookId: "PB-ENFORCE-FIDO2",
        name: "Enforce Phishing-Resistant MFA (Passkeys/FIDO2)",
        target: "sarah.jenkins@contoso.com",
        status: "Ready",
        description: "Mandates hardware security key requirement for all future sign-ins."
      }
    ]
  },
  {
    id: "INC-6218",
    incidentNumber: 6218,
    title: "Supply Chain Compromise & DLL Sideloading via CI/CD Worker Node",
    severity: "High",
    status: "Active",
    classification: "TruePositive",
    classificationReason: "SuspiciousActivity",
    createdTimeUtc: "2026-10-24T09:15:00Z",
    lastModifiedTimeUtc: "2026-10-24T12:00:00Z",
    assignedTo: "SecOps Tier 3 (Marcus K.)",
    tactics: ["InitialAccess", "Persistence", "PrivilegeEscalation", "CommandAndControl"],
    techniques: ["T1195.002", "T1574.002", "T1071.001"],
    description: "Sentinel detected anomalous build script execution on Azure DevOps self-hosted runner BUILD-AGENT-AZ04. A poisoned upstream npm package 'json-parse-secure-v2' executed pre-install scripts that sideloaded a trojanized DLL (version.dll) into the Azure runner daemon process, establishing an outbound HTTPS C2 tunnel.",
    summary: "Compromised open-source package dependency in CI/CD pipeline leading to persistent C2 beaconing. Source code repository access audited.",
    metrics: {
      riskScore: 91,
      confidenceScore: 96,
      blastRadius: "High (Azure DevOps Pipeline, GitHub Enterprise Orgs)",
      potentialDataLoss: "High"
    },
    entities: [
      {
        type: "Host",
        name: "BUILD-AGENT-AZ04",
        properties: {
          dnsHostName: "BUILD-AGENT-AZ04.dev.contoso.azure",
          osFamily: "Linux",
          osVersion: "Ubuntu 24.04 LTS",
          ipAddress: "10.2.1.18",
          defenderStatus: "Active"
        }
      },
      {
        type: "IP",
        name: "103.152.18.34",
        properties: {
          address: "103.152.18.34",
          country: "Singapore",
          asn: "AS13335 (Cloudflare / Bulletproof Subnet)",
          threatReputation: "Active Command and Control (C2) Server",
          threatScore: 97
        }
      },
      {
        type: "FileHash",
        name: "version.dll / agent_hook.so (SHA256)",
        properties: {
          fileName: "agent_hook.so",
          sha256: "7d793037a0760186574b0282f2f435e78921da8410294b4e995f55fa71c668ba",
          threatFamily: "Trojan:Linux/SideloadBackdoor.Gen!MTB"
        }
      }
    ],
    alerts: [
      {
        alertId: "ALT-71201",
        alertDisplayName: "Suspicious Preinstall Script Executed during Package Build",
        severity: "High",
        provider: "Microsoft Defender for Containers",
        timeGenerated: "2026-10-24T09:15:30Z",
        description: "npm build spawned curl piping to bash installing hidden binary in /tmp/.daemon",
        tactics: ["InitialAccess", "Execution"]
      },
      {
        alertId: "ALT-71202",
        alertDisplayName: "Encrypted C2 Beaconing to High-Risk IP",
        severity: "High",
        provider: "Microsoft Sentinel Network Analytics",
        timeGenerated: "2026-10-24T09:22:10Z",
        description: "Periodic beacon traffic every 60 seconds with jitter detected toward 103.152.18.34:443",
        tactics: ["CommandAndControl"]
      }
    ],
    timeline: [
      {
        time: "09:12 UTC",
        tactic: "Initial Access",
        phase: "Poisoned Dependency",
        details: "Build triggered with commit adding malicious dependency json-parse-secure-v2."
      },
      {
        time: "09:15 UTC",
        tactic: "Execution",
        phase: "Preinstall Hook",
        details: "Script downloaded encrypted payload and decrypted shared library."
      },
      {
        time: "09:22 UTC",
        tactic: "Command & Control",
        phase: "Beaconing Established",
        details: "Runner initiated encrypted heartbeats to C2 node in Singapore."
      }
    ],
    remediationPlaybooks: [
      {
        playbookId: "PB-ISOLATE-RUNNER",
        name: "Quarantine Azure DevOps Runner VM",
        target: "BUILD-AGENT-AZ04",
        status: "Completed",
        description: "Terminated agent session and unlinked VM from self-hosted pool."
      },
      {
        playbookId: "PB-REVOKE-PAT",
        name: "Rotate Azure DevOps Service Principal & PAT Tokens",
        target: "Azure DevOps Build Service",
        status: "Ready",
        description: "Rotates all CI/CD pipeline secrets and invalidates Personal Access Tokens."
      }
    ]
  },
  {
    id: "INC-5109",
    incidentNumber: 5109,
    title: "Anomalous Data Exfiltration via Azure Storage SAS Token",
    severity: "Medium",
    status: "Active",
    classification: "TruePositive",
    classificationReason: "SuspiciousActivity",
    createdTimeUtc: "2026-10-24T04:20:00Z",
    lastModifiedTimeUtc: "2026-10-24T08:00:00Z",
    assignedTo: "SecOps Tier 1 (Aisha M.)",
    tactics: ["Exfiltration", "Collection"],
    techniques: ["T1567.002", "T1530"],
    description: "Sentinel triggered on unusual egress traffic from storage account 'storagecontosoprod'. A contractor account created a Shared Access Signature (SAS) token with full container read permissions and downloaded 48GB of customer archive blobs to an unmanaged external IP address.",
    summary: "Large data egress via newly generated SAS token. Token revoked and contractor access suspended pending HR review.",
    metrics: {
      riskScore: 74,
      confidenceScore: 92,
      blastRadius: "Medium (Customer archive container)",
      potentialDataLoss: "Medium (48 GB)"
    },
    entities: [
      {
        type: "Account",
        name: "contractor-dev@contoso.com",
        properties: {
          accountName: "contractor-dev",
          userPrincipalName: "contractor-dev@contoso.com",
          riskLevel: "Medium",
          company: "External Cloud Partners Ltd"
        }
      },
      {
        type: "AzureResource",
        name: "storagecontosoprod/customer-pii-vault",
        properties: {
          resourceType: "Azure Storage Blob Container",
          accessTier: "Hot",
          egressVolumeGb: 48.2
        }
      },
      {
        type: "IP",
        name: "45.134.140.20",
        properties: {
          address: "45.134.140.20",
          country: "Netherlands",
          asn: "AS49981 (WorldStream B.V.)",
          threatReputation: "Commercial VPN / Hosting Provider",
          threatScore: 65
        }
      }
    ],
    alerts: [
      {
        alertId: "ALT-55101",
        alertDisplayName: "High Egress Volume from Azure Storage Account",
        severity: "Medium",
        provider: "Microsoft Defender for Cloud",
        timeGenerated: "2026-10-24T04:20:10Z",
        description: "Storage account egress exceeded baseline by 1,400% in 30 minutes",
        tactics: ["Exfiltration"]
      }
    ],
    timeline: [
      {
        time: "03:55 UTC",
        tactic: "Collection",
        phase: "SAS Generation",
        details: "Contractor generated 7-day SAS key with Read/List permissions on customer container."
      },
      {
        time: "04:10 UTC",
        tactic: "Exfiltration",
        phase: "Bulk Download",
        details: "Automated AzCopy tool initiated download of 48 GB compressed records."
      }
    ],
    remediationPlaybooks: [
      {
        playbookId: "PB-REVOKE-STORAGE-KEYS",
        name: "Regenerate Storage Account Access Keys & Revoke SAS",
        target: "storagecontosoprod",
        status: "Completed",
        description: "Regenerates primary and secondary storage keys, instantly rendering all existing SAS tokens invalid."
      }
    ]
  },
  {
    id: "INC-4470",
    incidentNumber: 4470,
    title: "Kerberoasting & Lateral Movement targeting Domain Controllers",
    severity: "High",
    status: "Active",
    classification: "TruePositive",
    classificationReason: "SuspiciousActivity",
    createdTimeUtc: "2026-10-23T20:00:00Z",
    lastModifiedTimeUtc: "2026-10-24T01:30:00Z",
    assignedTo: "SecOps Tier 2 (Elena R.)",
    tactics: ["CredentialAccess", "LateralMovement"],
    techniques: ["T1558.003", "T1003"],
    description: "Microsoft Defender for Identity detected multiple Kerberos Service Ticket (TGS) requests utilizing weak RC4 encryption for high-privilege service accounts (SPNs), followed by an attempt to access Active Directory database files on domain controller DC01.",
    summary: "Adversary attempting offline password cracking of service accounts. Active Directory Honey-Token triggered.",
    metrics: {
      riskScore: 82,
      confidenceScore: 94,
      blastRadius: "High (Domain Controller & Service Accounts)",
      potentialDataLoss: "Low"
    },
    entities: [
      {
        type: "Account",
        name: "svc_backup@CONTOSO.LOCAL",
        properties: {
          accountName: "svc_backup",
          spn: "MSSQLSvc/db01.contoso.local:1433",
          encryptionType: "RC4-HMAC",
          riskLevel: "High"
        }
      },
      {
        type: "Host",
        name: "DC01.CONTOSO.LOCAL",
        properties: {
          dnsHostName: "DC01.contoso.local",
          role: "Primary Domain Controller",
          ipAddress: "10.0.0.4"
        }
      },
      {
        type: "IP",
        name: "10.0.2.89",
        properties: {
          address: "10.0.2.89",
          internalHost: "WKS-DEV-19",
          threatReputation: "Originating internal attacking workstation"
        }
      }
    ],
    alerts: [
      {
        alertId: "ALT-44201",
        alertDisplayName: "Suspicious Kerberos TGS Requests (Kerberoasting)",
        severity: "High",
        provider: "Microsoft Defender for Identity",
        timeGenerated: "2026-10-23T20:01:14Z",
        description: "15 service ticket requests issued within 3 seconds using RC4 encryption",
        tactics: ["CredentialAccess"]
      }
    ],
    timeline: [
      {
        time: "19:55 UTC",
        tactic: "Discovery",
        phase: "SPN Enumeration",
        details: "LDAP query issued looking for user accounts with servicePrincipalName attributes."
      },
      {
        time: "20:01 UTC",
        tactic: "Credential Access",
        phase: "Kerberoast Ticket Request",
        details: "TGS-REQ sent requesting RC4 tickets for svc_backup and svc_sql."
      }
    ],
    remediationPlaybooks: [
      {
        playbookId: "PB-FORCE-AES-KERBEROS",
        name: "Force AES256 Encryption & Reset Service Password",
        target: "svc_backup@CONTOSO.LOCAL",
        status: "Ready",
        description: "Updates Active Directory service account to 32-character random string and disables RC4 cipher."
      }
    ]
  }
];

// Sample KQL queries & results for Log Analytics simulation
const mockKqlDatabase = {
  SecurityAlert: [
    { TimeGenerated: "2026-10-24T18:31:10Z", AlertName: "Rapid File Renaming & Encryption Activity", Severity: "Critical", ProviderName: "Microsoft Defender for Identity", CompromisedEntity: "SRV-FIN-SQL01" },
    { TimeGenerated: "2026-10-24T18:24:02Z", AlertName: "Inhibit System Recovery: Volume Shadow Copies Deleted", Severity: "High", ProviderName: "Microsoft Sentinel Analytics", CompromisedEntity: "SRV-FIN-SQL01" },
    { TimeGenerated: "2026-10-24T18:18:40Z", AlertName: "LSASS Memory Read for Credential Theft", Severity: "High", ProviderName: "Microsoft Defender for Endpoint", CompromisedEntity: "WKS-FIN-882" },
    { TimeGenerated: "2026-10-24T18:12:15Z", AlertName: "Suspicious Encoded PowerShell Command Execution", Severity: "High", ProviderName: "Microsoft Defender for Endpoint", CompromisedEntity: "WKS-FIN-882" },
    { TimeGenerated: "2026-10-24T14:40:05Z", AlertName: "Atypical Travel Detected", Severity: "High", ProviderName: "Microsoft Entra ID Protection", CompromisedEntity: "sarah.jenkins@contoso.com" },
    { TimeGenerated: "2026-10-24T09:22:10Z", AlertName: "Encrypted C2 Beaconing to High-Risk IP", Severity: "High", ProviderName: "Microsoft Sentinel Network Analytics", CompromisedEntity: "BUILD-AGENT-AZ04" }
  ],
  DeviceProcessEvents: [
    { TimeGenerated: "2026-10-24T18:24:02Z", DeviceName: "SRV-FIN-SQL01", FileName: "vssadmin.exe", ProcessCommandLine: "vssadmin.exe delete shadows /all /quiet", InitiatingProcessAccountName: "finance-admin" },
    { TimeGenerated: "2026-10-24T18:24:08Z", DeviceName: "SRV-FIN-SQL01", FileName: "wbadmin.exe", ProcessCommandLine: "wbadmin delete catalog -quiet", InitiatingProcessAccountName: "finance-admin" },
    { TimeGenerated: "2026-10-24T18:12:15Z", DeviceName: "WKS-FIN-882", FileName: "powershell.exe", ProcessCommandLine: "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc JABjAGwAaQBlAG4AdAAg...", InitiatingProcessAccountName: "finance-admin" },
    { TimeGenerated: "2026-10-24T18:29:45Z", DeviceName: "SRV-FIN-SQL01", FileName: "enc_locker.exe", ProcessCommandLine: "C:\\ProgramData\\UpdateMgr\\enc_locker.exe --path \\\\SRV-FIN-SQL01\\Accounting --threads 16", InitiatingProcessAccountName: "SYSTEM" }
  ],
  SigninLogs: [
    { TimeGenerated: "2026-10-24T14:40:02Z", UserPrincipalName: "sarah.jenkins@contoso.com", IPAddress: "194.26.29.112", Location: "Frankfurt, Germany", AppDisplayName: "OfficeHome", Status: "Success", RiskLevelDuringSignIn: "High" },
    { TimeGenerated: "2026-10-24T14:28:11Z", UserPrincipalName: "sarah.jenkins@contoso.com", IPAddress: "209.141.52.88", Location: "Seattle, WA, US", AppDisplayName: "OfficeHome", Status: "Success", RiskLevelDuringSignIn: "Low" },
    { TimeGenerated: "2026-10-24T18:05:00Z", UserPrincipalName: "finance-admin@contoso.com", IPAddress: "185.220.101.5", Location: "Seychelles", AppDisplayName: "Azure Virtual Desktop", Status: "Success", RiskLevelDuringSignIn: "High" }
  ],
  DeviceNetworkEvents: [
    { TimeGenerated: "2026-10-24T18:12:30Z", DeviceName: "WKS-FIN-882", RemoteIP: "185.220.101.5", RemotePort: 443, RemoteUrl: "https://185.220.101.5/payload.bin", InitiatingProcessFileName: "powershell.exe" },
    { TimeGenerated: "2026-10-24T09:22:10Z", DeviceName: "BUILD-AGENT-AZ04", RemoteIP: "103.152.18.34", RemotePort: 443, RemoteUrl: "https://103.152.18.34/heartbeat", InitiatingProcessFileName: "agent_hook.so" }
  ]
};

module.exports = {
  mockIncidents,
  mockKqlDatabase
};
