"""
OSINT Threat Intelligence Dashboard
-----------------------------------
A Python-based dashboard that collects, analyzes, and visualizes threat data 
from open-source intelligence feeds with MITRE ATT&CK framework mapping.

Author: [Your Name]
"""

import os
import json
import time
import hashlib
import requests
import pandas as pd
import numpy as np
import sqlite3
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
import seaborn as sns
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
from apscheduler.schedulers.background import BackgroundScheduler
import logging
from collections import Counter, defaultdict
import re
import csv
import threading
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("threat_dashboard.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key_change_in_production')

# Database setup
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'threat_intel.db')

def init_db():
    """Initialize the SQLite database with necessary tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # IOC table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ioc_type TEXT NOT NULL,
        value TEXT NOT NULL,
        source TEXT NOT NULL,
        description TEXT,
        first_seen TIMESTAMP NOT NULL,
        last_seen TIMESTAMP NOT NULL,
        confidence REAL,
        malware_family TEXT,
        threat_actor TEXT,
        campaign TEXT,
        tags TEXT,
        UNIQUE(ioc_type, value)
    )
    ''')
    
    # MITRE ATT&CK mappings
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS mitre_mappings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ioc_id INTEGER,
        technique_id TEXT NOT NULL,
        technique_name TEXT NOT NULL,
        tactic TEXT NOT NULL,
        source TEXT,
        confidence REAL,
        FOREIGN KEY (ioc_id) REFERENCES iocs (id),
        UNIQUE(ioc_id, technique_id)
    )
    ''')
    
    # Intelligence reports
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS intel_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        summary TEXT,
        source TEXT NOT NULL,
        publication_date TIMESTAMP NOT NULL,
        url TEXT,
        content TEXT,
        threat_actor TEXT,
        confidence REAL,
        severity TEXT,
        tags TEXT
    )
    ''')

    # Threat actors
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS threat_actors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        aliases TEXT,
        description TEXT,
        motivation TEXT,
        country TEXT,
        first_seen TIMESTAMP,
        last_seen TIMESTAMP,
        ttps TEXT,
        tools TEXT,
        targets TEXT,
        confidence REAL
    )
    ''')

    # Data sources
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS data_sources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        url TEXT,
        api_key TEXT,
        description TEXT,
        source_type TEXT,
        reliability REAL,
        last_fetch TIMESTAMP
    )
    ''')
    
    conn.commit()
    conn.close()
    logger.info("Database initialized successfully")

# OSINT Feed Collectors
class BaseOSINTCollector:
    """Base class for OSINT data collectors"""
    
    def __init__(self, name, url, api_key=None):
        self.name = name
        self.url = url
        self.api_key = api_key
        self.register_source()
    
    def register_source(self):
        """Register this data source in the database"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT OR IGNORE INTO data_sources (name, url, api_key, source_type) VALUES (?, ?, ?, ?)",
            (self.name, self.url, self.api_key, self.__class__.__name__)
        )
        
        conn.commit()
        conn.close()
    
    def update_last_fetch(self):
        """Update the last fetch timestamp for this source"""
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE data_sources SET last_fetch = ? WHERE name = ?",
            (datetime.now(), self.name)
        )
        
        conn.commit()
        conn.close()
    
    def collect(self):
        """Collect data from the source - to be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement collect()")


class AbuseIPDBCollector(BaseOSINTCollector):
    """Collects IP reputation data from AbuseIPDB"""
    
    def __init__(self, api_key):
        super().__init__("AbuseIPDB", "https://api.abuseipdb.com/api/v2/blacklist", api_key)
    
    def collect(self):
        """Collect blacklisted IPs from AbuseIPDB"""
        logger.info(f"Collecting data from {self.name}")
        
        headers = {
            'Key': self.api_key,
            'Accept': 'application/json',
        }
        
        params = {
            'confidenceMinimum': 90,
            'limit': 1000
        }
        
        try:
            response = requests.get(self.url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Process and store data
            current_time = datetime.now()
            for item in data.get('data', []):
                ip = item.get('ipAddress')
                confidence = item.get('abuseConfidenceScore')
                
                cursor.execute(
                    """
                    INSERT OR REPLACE INTO iocs
                    (ioc_type, value, source, first_seen, last_seen, confidence, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    ('ip', ip, self.name, current_time, current_time, confidence, 'malicious,blocklist')
                )
            
            conn.commit()
            conn.close()
            self.update_last_fetch()
            logger.info(f"Successfully collected {len(data.get('data', []))} IPs from {self.name}")
            
        except requests.RequestException as e:
            logger.error(f"Error collecting data from {self.name}: {str(e)}")


class AlienVaultOTXCollector(BaseOSINTCollector):
    """Collects threat intelligence from AlienVault OTX"""
    
    def __init__(self, api_key):
        super().__init__("AlienVault OTX", "https://otx.alienvault.com/api/v1/pulses/subscribed", api_key)
    
    def collect(self):
        """Collect threat intelligence from AlienVault OTX"""
        logger.info(f"Collecting data from {self.name}")
        
        headers = {
            'X-OTX-API-KEY': self.api_key,
        }
        
        try:
            # Get modified pulses from the last 24 hours
            yesterday = datetime.now() - timedelta(days=1)
            params = {
                'modified_since': yesterday.isoformat()
            }
            
            response = requests.get(self.url, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Process and store data
            current_time = datetime.now()
            for pulse in data.get('results', []):
                # Store the report information
                pulse_title = pulse.get('name', '')
                pulse_description = pulse.get('description', '')
                pulse_author = pulse.get('author_name', '')
                pulse_created = datetime.strptime(pulse.get('created', current_time.isoformat()), "%Y-%m-%dT%H:%M:%S.%f")
                pulse_url = f"https://otx.alienvault.com/pulse/{pulse.get('id')}"
                pulse_tags = ','.join(pulse.get('tags', []))
                
                cursor.execute(
                    """
                    INSERT INTO intel_reports
                    (title, summary, source, publication_date, url, content, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (pulse_title, pulse_description, self.name, pulse_created, pulse_url, pulse_description, pulse_tags)
                )
                report_id = cursor.lastrowid
                
                # Process IOCs
                for ioc_type, iocs in pulse.get('indicators', {}).items():
                    for ioc in iocs:
                        ioc_value = ioc.get('indicator')
                        ioc_type_normalized = self._normalize_ioc_type(ioc.get('type'))
                        
                        cursor.execute(
                            """
                            INSERT OR REPLACE INTO iocs
                            (ioc_type, value, source, description, first_seen, last_seen, tags)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (ioc_type_normalized, ioc_value, self.name, pulse_title, pulse_created, current_time, pulse_tags)
                        )
            
            conn.commit()
            conn.close()
            self.update_last_fetch()
            logger.info(f"Successfully collected data from {len(data.get('results', []))} pulses from {self.name}")
            
        except requests.RequestException as e:
            logger.error(f"Error collecting data from {self.name}: {str(e)}")
    
    def _normalize_ioc_type(self, otx_type):
        """Normalize OTX indicator types to our standardized types"""
        type_mapping = {
            'IPv4': 'ip',
            'IPv6': 'ip',
            'domain': 'domain',
            'hostname': 'domain',
            'email': 'email',
            'URL': 'url',
            'FileHash-MD5': 'hash',
            'FileHash-SHA1': 'hash',
            'FileHash-SHA256': 'hash',
            'FileHash-PEHASH': 'hash',
            'FileHash-IMPHASH': 'hash',
            'CIDR': 'cidr',
            'FilePath': 'file',
            'Mutex': 'mutex',
            'CVE': 'cve'
        }
        return type_mapping.get(otx_type, 'other')


class MITREATTCKCollector(BaseOSINTCollector):
    """Collects MITRE ATT&CK framework data"""
    
    def __init__(self):
        super().__init__("MITRE ATT&CK", "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
    
    def collect(self):
        """Collect MITRE ATT&CK data"""
        logger.info(f"Collecting data from {self.name}")
        
        try:
            response = requests.get(self.url)
            response.raise_for_status()
            data = response.json()
            
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Process and store data
            techniques = {}
            for obj in data.get('objects', []):
                if obj.get('type') == 'attack-pattern':
                    technique_id = obj.get('external_references', [{}])[0].get('external_id', '')
                    if not technique_id:
                        continue
                    
                    technique_name = obj.get('name', '')
                    description = obj.get('description', '')
                    
                    # Find the tactics (kill chain phases)
                    tactics = []
                    for phase in obj.get('kill_chain_phases', []):
                        if phase.get('kill_chain_name') == 'mitre-attack':
                            tactics.append(phase.get('phase_name', ''))
                    
                    tactics_str = ','.join(tactics)
                    
                    # Store the technique with its associated tactics
                    techniques[technique_id] = {
                        'name': technique_name,
                        'description': description,
                        'tactics': tactics_str
                    }
            
            # Store in a separate table or file for reference
            for technique_id, technique_info in techniques.items():
                for tactic in technique_info['tactics'].split(','):
                    if not tactic:
                        continue
                    
                    cursor.execute(
                        """
                        INSERT OR REPLACE INTO mitre_mappings
                        (technique_id, technique_name, tactic, source, confidence)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (technique_id, technique_info['name'], tactic, self.name, 100.0)
                    )
            
            conn.commit()
            conn.close()
            self.update_last_fetch()
            logger.info(f"Successfully collected {len(techniques)} techniques from {self.name}")
            
        except requests.RequestException as e:
            logger.error(f"Error collecting data from {self.name}: {str(e)}")


# Data Analysis
class ThreatIntelAnalyzer:
    """Analyzes threat intelligence data from the database"""
    
    def get_ioc_statistics(self):
        """Get statistics on IOCs in the database"""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # IOCs by type
        cursor.execute("SELECT ioc_type, COUNT(*) as count FROM iocs GROUP BY ioc_type")
        ioc_types = {row['ioc_type']: row['count'] for row in cursor.fetchall()}
        
        # IOCs by source
        cursor.execute("SELECT source, COUNT(*) as count FROM iocs GROUP BY source")
        ioc_sources = {row['source']: row['count'] for row in cursor.fetchall()}
        
        # IOCs by time (last 7 days)
        cursor.execute(
            """
            SELECT date(first_seen) as date, COUNT(*) as count 
            FROM iocs 
            WHERE first_seen >= date('now', '-7 days')
            GROUP BY date(first_seen)
            ORDER BY date(first_seen)
            """
        )
        ioc_timeline = {row['date']: row['count'] for row in cursor.fetchall()}
        
        conn.close()
        
        return {
            'by_type': ioc_types,
            'by_source': ioc_sources,
            'timeline': ioc_timeline
        }
    
    def get_mitre_statistics(self):
        """Get statistics on MITRE ATT&CK mappings"""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Techniques by tactic
        cursor.execute(
            """
            SELECT tactic, COUNT(*) as count 
            FROM mitre_mappings 
            GROUP BY tactic
            """
        )
        tactics = {row['tactic']: row['count'] for row in cursor.fetchall()}
        
        # Most common techniques
        cursor.execute(
            """
            SELECT technique_id, technique_name, tactic, COUNT(*) as count 
            FROM mitre_mappings 
            GROUP BY technique_id 
            ORDER BY count DESC 
            LIMIT 10
            """
        )
        top_techniques = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            'by_tactic': tactics,
            'top_techniques': top_techniques
        }
    
    def search_iocs(self, query, ioc_type=None):
        """Search for IOCs in the database"""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if ioc_type:
            cursor.execute(
                """
                SELECT * FROM iocs 
                WHERE ioc_type = ? AND value LIKE ? 
                ORDER BY last_seen DESC
                """,
                (ioc_type, f"%{query}%")
            )
        else:
            cursor.execute(
                """
                SELECT * FROM iocs 
                WHERE value LIKE ? OR description LIKE ? OR tags LIKE ?
                ORDER BY last_seen DESC
                """,
                (f"%{query}%", f"%{query}%", f"%{query}%")
            )
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return results
    
    def get_related_iocs(self, ioc_value, max_results=10):
        """Find IOCs that are related to the given IOC"""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Find reports that mention this IOC
        cursor.execute(
            """
            SELECT intel_reports.id
            FROM iocs
            JOIN intel_reports ON iocs.source = intel_reports.source
            WHERE iocs.value = ?
            """,
            (ioc_value,)
        )
        report_ids = [row['id'] for row in cursor.fetchall()]
        
        if not report_ids:
            conn.close()
            return []
        
        # Find other IOCs mentioned in the same reports
        placeholders = ','.join(['?'] * len(report_ids))
        cursor.execute(
            f"""
            SELECT DISTINCT iocs.* 
            FROM iocs
            JOIN intel_reports ON iocs.source = intel_reports.source
            WHERE intel_reports.id IN ({placeholders})
            AND iocs.value != ?
            ORDER BY iocs.last_seen DESC
            LIMIT ?
            """,
            report_ids + [ioc_value, max_results]
        )
        
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return results
    
    def generate_executive_report(self):
        """Generate an executive-level summary report"""
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Get time period for the report (last 7 days)
        seven_days_ago = (datetime.now() - timedelta(days=7)).strftime('%d-%m-%y')
        
        # Get new IOC counts by type
        cursor.execute(
            """
            SELECT ioc_type, COUNT(*) as count 
            FROM iocs 
            WHERE first_seen >= ?
            GROUP BY ioc_type
            """,
            (seven_days_ago,)
        )
        new_iocs = {row['ioc_type']: row['count'] for row in cursor.fetchall()}
        
        # Get new reports
        cursor.execute(
            """
            SELECT COUNT(*) as count 
            FROM intel_reports 
            WHERE publication_date >= ?
            """,
            (seven_days_ago,)
        )
        new_reports = cursor.fetchone()['count']
        
        # Get top MITRE techniques
        cursor.execute(
            """
            SELECT technique_id, technique_name, COUNT(*) as count 
            FROM mitre_mappings 
            GROUP BY technique_id 
            ORDER BY count DESC 
            LIMIT 5
            """
        )
        top_techniques = [dict(row) for row in cursor.fetchall()]
        
        # Top tactics
        cursor.execute(
            """
            SELECT tactic, COUNT(*) as count 
            FROM mitre_mappings 
            GROUP BY tactic 
            ORDER BY count DESC 
            LIMIT 5
            """
        )
        top_tactics = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            'period': f"{seven_days_ago} to {datetime.now().strftime('%Y-%m-%d')}",
            'new_iocs': new_iocs,
            'total_new_iocs': sum(new_iocs.values()),
            'new_reports': new_reports,
            'top_techniques': top_techniques,
            'top_tactics': top_tactics
        }


# Flask routes for the dashboard UI
@app.route('/')
def index():
    """Dashboard home page"""
    analyzer = ThreatIntelAnalyzer()
    exec_report = analyzer.generate_executive_report()
    
    return render_template(
        'index.html',
        exec_report=exec_report
    )

@app.route('/iocs')
def iocs():
    """IOC browser page"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get the latest IOCs, paginated
    page = int(request.args.get('page', 1))
    per_page = 50
    offset = (page - 1) * per_page
    
    cursor.execute(
        """
        SELECT * FROM iocs 
        ORDER BY last_seen DESC 
        LIMIT ? OFFSET ?
        """,
        (per_page, offset)
    )
    
    iocs = [dict(row) for row in cursor.fetchall()]
    
    # Get total count for pagination
    cursor.execute("SELECT COUNT(*) as count FROM iocs")
    total = cursor.fetchone()['count']
    
    conn.close()
    
    return render_template(
        'iocs.html',
        iocs=iocs,
        page=page,
        per_page=per_page,
        total=total
    )

@app.route('/api/iocs', methods=['DELETE'])
def api_delete_ioc_by_value():
    """API endpoint to delete an IOC by type and value"""
    try:
        ioc_type = request.json.get('ioc_type')
        value = request.json.get('value')
        
        if not ioc_type or not value:
            return jsonify({
                'success': False,
                'message': 'Both ioc_type and value are required'
            }), 400
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # First, get the IOC ID
        cursor.execute("SELECT id FROM iocs WHERE ioc_type = ? AND value = ?", (ioc_type, value))
        result = cursor.fetchone()
        
        if not result:
            conn.close()
            return jsonify({
                'success': False,
                'message': f'No IOC found with type {ioc_type} and value {value}'
            }), 404
        
        ioc_id = result[0]
        
        # Delete any MITRE ATT&CK mappings
        cursor.execute("DELETE FROM mitre_mappings WHERE ioc_id = ?", (ioc_id,))
        
        # Then delete the IOC
        cursor.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': f'IOC with type {ioc_type} and value {value} deleted successfully'
        })
        
    except Exception as e:
        logger.error(f"Error deleting IOC: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error deleting IOC: {str(e)}'
        }), 500

@app.route('/api/iocs/<int:ioc_id>', methods=['DELETE'])
def api_delete_ioc(ioc_id):
    """API endpoint to delete an IOC by ID"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # First, delete any MITRE ATT&CK mappings
        cursor.execute("DELETE FROM mitre_mappings WHERE ioc_id = ?", (ioc_id,))
        
        # Then delete the IOC
        cursor.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))
        
        # Check if anything was actually deleted
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({
                'success': False,
                'message': f'No IOC found with ID {ioc_id}'
            }), 404
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': f'IOC with ID {ioc_id} deleted successfully'
        })
        
    except Exception as e:
        logger.error(f"Error deleting IOC: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error deleting IOC: {str(e)}'
        }), 500
    
@app.route('/api/iocs', methods=['POST'])
def api_add_ioc():
    """API endpoint to add a new IOC"""
    try:
        data = request.json
        
        if not data or 'value' not in data or 'ioc_type' not in data:
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Extract data with defaults
        ioc_type = data.get('ioc_type')
        value = data.get('value')
        source = data.get('source', 'API Input')
        description = data.get('description', '')
        confidence = float(data.get('confidence', 50))
        malware_family = data.get('malware_family')
        threat_actor = data.get('threat_actor')
        campaign = data.get('campaign')
        tags = data.get('tags', '')
        
        current_time = datetime.now()
        
        # Save to database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                """
                INSERT INTO iocs
                (ioc_type, value, source, description, first_seen, last_seen, confidence, 
                malware_family, threat_actor, campaign, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (ioc_type, value, source, description, current_time, current_time, confidence, 
                 malware_family, threat_actor, campaign, tags)
            )
            
            ioc_id = cursor.lastrowid
            
            # Handle MITRE ATT&CK mappings if provided
            if 'mitre_mappings' in data and isinstance(data['mitre_mappings'], list):
                for mapping in data['mitre_mappings']:
                    if all(k in mapping for k in ['technique_id', 'technique_name', 'tactic']):
                        cursor.execute(
                            """
                            INSERT INTO mitre_mappings
                            (ioc_id, technique_id, technique_name, tactic, source, confidence)
                            VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (ioc_id, mapping['technique_id'], mapping['technique_name'], 
                             mapping['tactic'], 'API Input', confidence)
                        )
            
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': 'IOC added successfully',
                'id': ioc_id
            })
            
        except Exception as e:
            conn.rollback()
            conn.close()
            raise e
    
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error adding IOC: {str(e)}'
        }), 500
    
@app.route('/mitre')
def mitre():
    """MITRE ATT&CK framework page"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Techniques by tactic
    cursor.execute(
        """
        SELECT tactic, COUNT(*) as count 
        FROM mitre_mappings 
        GROUP BY tactic
        """
    )
    tactics = {row['tactic']: row['count'] for row in cursor.fetchall()}
    
    # Most common techniques
    cursor.execute(
        """
        SELECT technique_id, technique_name, tactic, COUNT(*) as count 
        FROM mitre_mappings 
        GROUP BY technique_id 
        ORDER BY count DESC 
        LIMIT 10
        """
    )
    top_techniques = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    mitre_stats = {
        'by_tactic': tactics,
        'top_techniques': top_techniques
    }
    
    return render_template(
        'mitre.html',
        mitre_stats=mitre_stats
    )

@app.route('/reports')
def reports():
    """Intelligence reports page"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get the latest reports, paginated
    page = int(request.args.get('page', 1))
    per_page = 20
    offset = (page - 1) * per_page
    
    cursor.execute(
        """
        SELECT * FROM intel_reports
        ORDER BY publication_date DESC
        LIMIT ? OFFSET ?
        """,
        (per_page, offset)
    )
    
    reports = [dict(row) for row in cursor.fetchall()]
    
    # Get total count for pagination
    cursor.execute("SELECT COUNT(*) as count FROM intel_reports")
    total = cursor.fetchone()['count']
    
    conn.close()
    
    return render_template(
        'reports.html',
        reports=reports,
        page=page,
        per_page=per_page,
        total=total
    )

@app.route('/search')
def search():
    """Search page"""
    query = request.args.get('q', '')
    ioc_type = request.args.get('type', None)
    
    if not query:
        return render_template('search.html', results=[], query='')
    
    analyzer = ThreatIntelAnalyzer()
    results = analyzer.search_iocs(query, ioc_type)
    
    return render_template(
        'search.html',
        results=results,
        query=query,
        ioc_type=ioc_type
    )

@app.route('/api/stats/iocs')
def api_ioc_stats():
    """API endpoint for IOC statistics"""
    analyzer = ThreatIntelAnalyzer()
    stats = analyzer.get_ioc_statistics()
    return jsonify(stats)

@app.route('/api/stats/mitre')
def api_mitre_stats():
    """API endpoint for MITRE statistics"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Techniques by tactic
    cursor.execute(
        """
        SELECT tactic, COUNT(*) as count 
        FROM mitre_mappings 
        GROUP BY tactic
        """
    )
    tactics = {row['tactic']: row['count'] for row in cursor.fetchall()}
    
    # Most common techniques
    cursor.execute(
        """
        SELECT technique_id, technique_name, tactic, COUNT(*) as count 
        FROM mitre_mappings 
        GROUP BY technique_id 
        ORDER BY count DESC 
        LIMIT 10
        """
    )
    top_techniques = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    # Log what we're returning
    logger.info(f"MITRE stats: {len(top_techniques)} techniques, {len(tactics)} tactics")
    
    result = {
        'by_tactic': tactics,
        'top_techniques': top_techniques
    }
    
    return jsonify(result)

@app.route('/api/mitre/technique/<technique_id>/iocs')
def api_mitre_technique_iocs(technique_id):
    """API endpoint for IOCs associated with a MITRE technique"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute(
        """
        SELECT iocs.* 
        FROM iocs
        JOIN mitre_mappings ON iocs.id = mitre_mappings.ioc_id
        WHERE mitre_mappings.technique_id = ?
        """,
        (technique_id,)
    )
    
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(results)


@app.route('/api/iocs/related')
def api_related_iocs():
    """API endpoint for related IOCs"""
    ioc_value = request.args.get('value', '')
    
    if not ioc_value:
        return jsonify([])
    
    analyzer = ThreatIntelAnalyzer()
    results = analyzer.get_related_iocs(ioc_value)
    
    return jsonify(results)


@app.route('/api/reports/<int:report_id>')
def api_report_details(report_id):
    """API endpoint for report details"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute(
        "SELECT * FROM intel_reports WHERE id = ?",
        (report_id,)
    )
    
    report = dict(cursor.fetchone() or {})
    conn.close()
    
    return jsonify(report)


@app.route('/api/reports/<int:report_id>/iocs')
def api_report_iocs(report_id):
    """API endpoint for IOCs associated with a report"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get the report to find the source
    cursor.execute(
        "SELECT source FROM intel_reports WHERE id = ?",
        (report_id,)
    )
    report = cursor.fetchone()
    
    if not report:
        return jsonify([])
    
    # Find IOCs from the same source with the same date range
    cursor.execute(
        """
        SELECT iocs.* 
        FROM iocs
        JOIN intel_reports ON iocs.source = intel_reports.source
        WHERE intel_reports.id = ?
        """,
        (report_id,)
    )
    
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(results)


@app.route('/api/stats/mitre/export')
def api_mitre_export():
    """API endpoint for exporting MITRE data"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute(
        """
        SELECT technique_id, technique_name, tactic, COUNT(*) as count
        FROM mitre_mappings
        GROUP BY technique_id, tactic
        ORDER BY count DESC
        """
    )
    
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(results)

# Admin route for adding IOCs
@app.route('/admin/add-ioc', methods=['GET', 'POST'])
def admin_add_ioc():
    """Admin interface to add new IOCs"""
    if request.method == 'POST':
        # Get form data
        ioc_type = request.form.get('ioc_type')
        value = request.form.get('value')
        source = request.form.get('source')
        description = request.form.get('description')
        confidence = request.form.get('confidence')
        malware_family = request.form.get('malware_family') or None
        threat_actor = request.form.get('threat_actor') or None
        campaign = request.form.get('campaign') or None
        tags = request.form.get('tags')
        
        # Get MITRE ATT&CK mappings
        technique_ids = request.form.getlist('technique_id[]')
        technique_names = request.form.getlist('technique_name[]')
        tactics = request.form.getlist('tactic[]')
        
        current_time = datetime.now()
        
        # Save to database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        try:
            # Insert IOC
            cursor.execute(
                """
                INSERT INTO iocs
                (ioc_type, value, source, description, first_seen, last_seen, confidence, malware_family, threat_actor, campaign, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (ioc_type, value, source, description, current_time, current_time, confidence, 
                 malware_family, threat_actor, campaign, tags)
            )
            
            # Get the inserted IOC's ID
            ioc_id = cursor.lastrowid
            
            # Insert MITRE mappings
            for i in range(len(technique_ids)):
                if technique_ids[i] and tactics[i]:  # Only add if both fields are filled
                    cursor.execute(
                        """
                        INSERT INTO mitre_mappings
                        (ioc_id, technique_id, technique_name, tactic, source, confidence)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (ioc_id, technique_ids[i], technique_names[i], tactics[i], 'Manual Entry', confidence)
                    )
            
            conn.commit()
            conn.close()
            
            flash('IOC added successfully!', 'success')
            return redirect(url_for('iocs'))
            
        except Exception as e:
            conn.rollback()
            conn.close()
            flash(f'Error adding IOC: {str(e)}', 'danger')
            return render_template('admin/add_ioc.html')
    
    # GET request - show the form
    return render_template('admin/add_ioc.html')

# Data collection scheduler
def setup_scheduler():
    """Set up the background scheduler for data collection"""
    scheduler = BackgroundScheduler()
    
    # Set up collectors
    # Note: In a real application, these API keys would be loaded from environment variables
    collectors = [
        AbuseIPDBCollector('YOUR_ABUSEIPDB_API_KEY'),
        AlienVaultOTXCollector('YOUR_OTX_API_KEY'),
        MITREATTCKCollector()
    ]
    
    # Schedule collection jobs
    for collector in collectors:
        # Different collection frequencies based on the source
        if isinstance(collector, MITREATTCKCollector):
            # MITRE ATT&CK data doesn't change often
            scheduler.add_job(
                collector.collect,
                'interval',
                days=7,
                id=f'collect_{collector.name.replace(" ", "_").lower()}'
            )
        else:
            # More frequent collection for threat intel feeds
            scheduler.add_job(
                collector.collect,
                'interval',
                hours=6,
                id=f'collect_{collector.name.replace(" ", "_").lower()}'
            )
    
    scheduler.start()
    logger.info("Background scheduler started")
    return scheduler

# Main application entry point
if __name__ == '__main__':
    # Initialize the database
    init_db()
    
    # Set up data collection scheduler
    scheduler = setup_scheduler()
    
    try:
        # Run the Flask application
        app.run(debug=True, use_reloader=False)
    finally:
        # Shut down the scheduler when the app exits
        scheduler.shutdown()