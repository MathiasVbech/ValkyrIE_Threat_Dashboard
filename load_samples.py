#!/usr/bin/env python3
"""
load_samples.py - Script to load 10 sample IOCs with MITRE mappings into ValkyrIE database
Usage: python3 load_samples.py [database_path]
Default database path: ./threat_intel.db
"""

import os
import sys
import sqlite3
import random
from datetime import datetime, timedelta

# Get database path from command line or use default
if len(sys.argv) > 1:
    DB_PATH = sys.argv[1]
else:
    DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'threat_intel.db')

# Check if database exists
if not os.path.exists(DB_PATH):
    print(f"Error: Database file '{DB_PATH}' not found.")
    print("Make sure to run this script from the same directory as your ValkyrIE dashboard")
    print("or provide the correct path to the database file as an argument.")
    sys.exit(1)

# Sample IOCs
SAMPLE_IOCS = [
    ('ip', '45.61.138.109', 'FireEye', 'C2 server for APT29 operations', 95, 'Cobalt Strike', 'APT29', 'Cozy Bear Campaign', 'malicious,apt,c2'),
    ('domain', 'cdn-telecom.net', 'Mandiant', 'Phishing domain used in targeted attacks', 90, 'Emotet', 'TA505', 'Financial Sector Campaign', 'phishing,banking,malware'),
    ('hash', 'b0ad4e4f14212e7c2f768f91cd4888a7a8a4fb89', 'CrowdStrike', 'Dropper for Ryuk ransomware', 95, 'Ryuk', 'Wizard Spider', 'Healthcare Targeting', 'ransomware,healthcare,dropper'),
    ('url', 'https://update-service.microsoft-cdn.org/download.php', 'Recorded Future', 'Fake Microsoft update site', 88, 'SocGholish', 'Evil Corp', 'Fake Update Campaign', 'phishing,fake-update,malware'),
    ('ip', '194.31.98.124', 'AlienVault OTX', 'Ransomware payment server', 92, 'BlackCat', 'ALPHV', 'BlackCat Ransomware', 'ransomware,payment,bitcoin'),
    ('email', 'accounts@secure-banking-portal.com', 'PhishLabs', 'Banking phishing campaign', 85, 'BazaLoader', 'TA551', 'Banking Credential Theft', 'phishing,banking,credentials'),
    ('domain', 'secure-document-vault.com', 'Proofpoint', 'Document sharing phishing site', 87, 'IcedID', 'TA577', 'Document Phishing', 'phishing,document,credentials'),
    ('hash', '8eb49b4618e55fe1d3f38dad0afdcab7fad0bae3', 'Microsoft', 'Backdoor implant', 93, 'Sunburst', 'UNC2452', 'SolarWinds Campaign', 'backdoor,supply-chain,apt'),
    ('ip', '91.219.236.166', 'Cisco Talos', 'Botnet command server', 91, 'Trickbot', 'TA542', 'Banking Fraud', 'botnet,banking,c2'),
    ('url', 'https://drive.google.com/file/d/1KjhdfHU782jhHkjhkjKJYU/view', 'Symantec', 'Malicious document link', 89, 'AgentTesla', 'TA407', 'Energy Sector Attacks', 'phishing,infostealer,energy-sector')
]

# MITRE ATT&CK techniques
MITRE_TECHNIQUES = [
    ('T1566', 'Phishing', 'initial-access'),
    ('T1204', 'User Execution', 'execution'),
    ('T1027', 'Obfuscated Files or Information', 'defense-evasion'),
    ('T1059.003', 'Windows Command Shell', 'execution'),
    ('T1486', 'Data Encryption for Impact', 'impact'),
    ('T1082', 'System Information Discovery', 'discovery'),
    ('T1083', 'File and Directory Discovery', 'discovery'),
    ('T1018', 'Remote System Discovery', 'discovery'),
    ('T1071', 'Application Layer Protocol', 'command-and-control'),
    ('T1567', 'Exfiltration Over Web Service', 'exfiltration'),
    ('T1497', 'Virtualization/Sandbox Evasion', 'defense-evasion'),
    ('T1078', 'Valid Accounts', 'defense-evasion'),
    ('T1569', 'System Services', 'execution'),
    ('T1087', 'Account Discovery', 'discovery'),
    ('T1053', 'Scheduled Task/Job', 'persistence')
]

# Sample intel reports
SAMPLE_REPORTS = [
    ('APT29 Campaign Targeting Government Entities', 'Analysis of recent APT29 activities targeting government infrastructure in Europe', 'FireEye', '2025-03-05 14:30:00', 'https://example.com/apt29-report', 'Detailed analysis of TTPs used by APT29 in their latest campaign targeting government entities across Europe. The threat actor used spear-phishing emails with malicious attachments to gain initial access.', 'APT29', 90, 'High', 'apt29,government,russia'),
    ('Emotet Resurgence with New Evasion Techniques', 'Investigation into the latest Emotet distribution techniques after recent takedown attempts', 'Proofpoint', '2025-03-08 09:15:00', 'https://example.com/emotet-report', 'After a brief hiatus, Emotet has returned with enhanced evasion capabilities and a new focus on financial institutions. The malware now uses multi-stage downloaders and improved anti-analysis techniques.', 'TA505', 85, 'Medium', 'emotet,malware,evasion'),
    ('Ryuk Ransomware Targeting Critical Infrastructure', 'Analysis of ransomware campaigns against critical infrastructure organizations', 'CrowdStrike', '2025-03-10 11:45:00', 'https://example.com/ryuk-report', 'This report analyzes the recent surge in Ryuk ransomware attacks targeting critical infrastructure providers. The threat actors are demanding increasingly large ransom payments and employing more sophisticated lateral movement techniques.', 'Wizard Spider', 95, 'High', 'ransomware,critical-infrastructure,ryuk')
]

def generate_date_in_past(days_ago_min=1, days_ago_max=30):
    """Generate a random date within the specified range of days ago"""
    days_ago = random.randint(days_ago_min, days_ago_max)
    return datetime.now() - timedelta(days=days_ago)

def load_samples():
    """Load sample IOCs, reports, and MITRE mappings into the database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Counter for added items
        iocs_added = 0
        mappings_added = 0
        reports_added = 0
        
        # Add IOCs
        current_time = datetime.now()
        for ioc_data in SAMPLE_IOCS:
            ioc_type, value, source, description, confidence, malware, actor, campaign, tags = ioc_data
            
            # Generate random first seen date in the past
            first_seen = generate_date_in_past(5, 60)
            
            cursor.execute(
                """
                INSERT OR IGNORE INTO iocs
                (ioc_type, value, source, description, first_seen, last_seen, confidence, 
                malware_family, threat_actor, campaign, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (ioc_type, value, source, description, first_seen, current_time, confidence, 
                malware, actor, campaign, tags)
            )
            
            if cursor.rowcount > 0:
                iocs_added += 1
                
                # Get the IOC ID (either the new one or existing one)
                if cursor.lastrowid:
                    ioc_id = cursor.lastrowid
                else:
                    cursor.execute("SELECT id FROM iocs WHERE ioc_type = ? AND value = ?", 
                                (ioc_type, value))
                    ioc_id = cursor.fetchone()[0]
                
                # Add 2-3 random MITRE mappings
                num_techniques = random.randint(2, 3)
                selected_techniques = random.sample(MITRE_TECHNIQUES, num_techniques)
                
                for technique in selected_techniques:
                    tech_id, tech_name, tactic = technique
                    cursor.execute(
                        """
                        INSERT OR IGNORE INTO mitre_mappings
                        (ioc_id, technique_id, technique_name, tactic, source, confidence)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (ioc_id, tech_id, tech_name, tactic, source, confidence)
                    )
                    if cursor.rowcount > 0:
                        mappings_added += 1
        
        # Add reports
        for report_data in SAMPLE_REPORTS:
            title, summary, source, published_date, url, content, actor, confidence, severity, tags = report_data
            
            cursor.execute(
                """
                INSERT OR IGNORE INTO intel_reports
                (title, summary, source, publication_date, url, content, threat_actor, confidence, severity, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                report_data
            )
            if cursor.rowcount > 0:
                reports_added += 1
        
        conn.commit()
        conn.close()
        
        print(f"Successfully loaded sample data into {DB_PATH}:")
        print(f"- {iocs_added} IOCs added")
        print(f"- {mappings_added} MITRE mappings added")
        print(f"- {reports_added} intelligence reports added")
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    load_samples()