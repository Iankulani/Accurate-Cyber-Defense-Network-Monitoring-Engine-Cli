#!/usr/bin/env python3
"""
Author Ian Carter Kulani
"""

import asyncio
import threading
import socket
import struct
import time
import json
import logging
import sqlite3
import subprocess
import requests
import psutil
from datetime import datetime, timedelta
from collections import defaultdict, deque
import scapy.all as scapy
from scapy.all import IP, TCP, UDP, ICMP, sniff
import dpkt
import nmap
import geoip2.database
from telegram import Update, Bot
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Tuple
import argparse
import sys
import os
import re
from pathlib import Path
import select
import random

# =============================================================================
# CONFIGURATION AND CONSTANTS
# =============================================================================

class Config:
    """Configuration management class"""
    def __init__(self):
        self.config_file = "cyber_monitor_config.json"
        self.db_file = "cyber_monitor.db"
        self.log_file = "cyber_monitor.log"
        self.telegram_token = None
        self.telegram_chat_id = None
        self.monitored_ips = set()
        self.alert_thresholds = {
            'tcp_flood': 1000,    # packets per second
            'udp_flood': 1000,    # packets per second
            'port_scan': 50,      # ports per minute
            'syn_flood': 500,     # SYN packets per second
            'icmp_flood': 500,    # ICMP packets per second
        }
        self.purple_theme = {
            'primary': '#8A2BE2',
            'secondary': '#9370DB',
            'accent': '#4B0082',
            'background': '#2C003E',
            'text': '#E6E6FA'
        }
        self.load_config()
    
    def load_config(self):
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    self.telegram_token = data.get('telegram_token')
                    self.telegram_chat_id = data.get('telegram_chat_id')
                    self.monitored_ips = set(data.get('monitored_ips', []))
        except Exception as e:
            logging.error(f"Error loading config: {e}")
    
    def save_config(self):
        """Save configuration to file"""
        try:
            data = {
                'telegram_token': self.telegram_token,
                'telegram_chat_id': self.telegram_chat_id,
                'monitored_ips': list(self.monitored_ips)
            }
            with open(self.config_file, 'w') as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            logging.error(f"Error saving config: {e}")

# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class ThreatEvent:
    """Data class for threat events"""
    id: int
    timestamp: datetime
    threat_type: str
    source_ip: str
    target_ip: str
    severity: str
    description: str
    packet_count: int
    port: Optional[int] = None
    protocol: Optional[str] = None

@dataclass
class NetworkStats:
    """Data class for network statistics"""
    timestamp: datetime
    ip_address: str
    packets_received: int
    packets_sent: int
    tcp_connections: int
    udp_connections: int
    bandwidth_usage: float

@dataclass
class PortScanResult:
    """Data class for port scan results"""
    ip_address: str
    port: int
    protocol: str
    status: str
    service: str
    banner: str
    timestamp: datetime

# =============================================================================
# DATABASE MANAGEMENT
# =============================================================================

class DatabaseManager:
    """Database management for storing threats and statistics"""
    
    def __init__(self, db_file: str):
        self.db_file = db_file
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Threats table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    threat_type TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    target_ip TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    packet_count INTEGER,
                    port INTEGER,
                    protocol TEXT
                )
            ''')
            
            # Network stats table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT NOT NULL,
                    packets_received INTEGER,
                    packets_sent INTEGER,
                    tcp_connections INTEGER,
                    udp_connections INTEGER,
                    bandwidth_usage REAL
                )
            ''')
            
            # Port scans table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS port_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    status TEXT NOT NULL,
                    service TEXT,
                    banner TEXT
                )
            ''')
            
            # Command history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS command_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    command TEXT NOT NULL,
                    parameters TEXT,
                    success BOOLEAN
                )
            ''')
            
            # Reports table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    report_type TEXT NOT NULL,
                    period TEXT NOT NULL,
                    data TEXT NOT NULL
                )
            ''')
            
            conn.commit()
            conn.close()
            logging.info("Database initialized successfully")
            
        except Exception as e:
            logging.error(f"Error initializing database: {e}")
    
    def log_threat(self, threat: ThreatEvent):
        """Log threat event to database"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO threats 
                (timestamp, threat_type, source_ip, target_ip, severity, description, packet_count, port, protocol)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                threat.timestamp, threat.threat_type, threat.source_ip, threat.target_ip,
                threat.severity, threat.description, threat.packet_count, threat.port, threat.protocol
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            logging.error(f"Error logging threat: {e}")
            return False
    
    def get_recent_threats(self, hours: int = 24) -> List[ThreatEvent]:
        """Get recent threats from database"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            cursor.execute('''
                SELECT id, timestamp, threat_type, source_ip, target_ip, severity, 
                       description, packet_count, port, protocol
                FROM threats 
                WHERE timestamp > ?
                ORDER BY timestamp DESC
            ''', (cutoff_time,))
            
            threats = []
            for row in cursor.fetchall():
                threat = ThreatEvent(*row)
                threats.append(threat)
            
            conn.close()
            return threats
        except Exception as e:
            logging.error(f"Error getting threats: {e}")
            return []
    
    # Additional database methods for stats, port scans, command history, etc.
    # ... (implement similar methods for other database operations)

# =============================================================================
# NETWORK MONITORING ENGINE
# =============================================================================

class NetworkMonitor:
    """Core network monitoring engine"""
    
    def __init__(self, config: Config, db_manager: DatabaseManager):
        self.config = config
        self.db_manager = db_manager
        self.is_monitoring = False
        self.packet_stats = defaultdict(lambda: defaultdict(int))
        self.port_scan_detector = PortScanDetector(config)
        self.ddos_detector = DDoSDetector(config)
        self.flood_detector = FloodDetector(config)
        
        # Statistics tracking
        self.packet_counts = defaultdict(lambda: deque(maxlen=1000))
        self.connection_attempts = defaultdict(lambda: deque(maxlen=1000))
        self.start_time = datetime.now()
    
    def start_monitoring(self, target_ip: str = None):
        """Start network monitoring"""
        try:
            self.is_monitoring = True
            if target_ip:
                self.config.monitored_ips.add(target_ip)
                self.config.save_config()
            
            # Start packet capture in separate thread
            monitor_thread = threading.Thread(
                target=self._packet_capture_loop,
                daemon=True
            )
            monitor_thread.start()
            
            # Start analysis thread
            analysis_thread = threading.Thread(
                target=self._analysis_loop,
                daemon=True
            )
            analysis_thread.start()
            
            logging.info(f"Started monitoring: {target_ip or 'all traffic'}")
            return True
            
        except Exception as e:
            logging.error(f"Error starting monitoring: {e}")
            return False
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.is_monitoring = False
        logging.info("Stopped network monitoring")
    
    def _packet_capture_loop(self):
        """Main packet capture loop"""
        try:
            while self.is_monitoring:
                # Use scapy for packet capture
                sniff(
                    prn=self._process_packet,
                    count=100,
                    timeout=10,
                    filter="ip"  # Capture IP packets only
                )
        except Exception as e:
            logging.error(f"Packet capture error: {e}")
    
    def _process_packet(self, packet):
        """Process captured packet"""
        try:
            if IP in packet:
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                
                # Only process packets related to monitored IPs
                if (src_ip in self.config.monitored_ips or 
                    dst_ip in self.config.monitored_ips):
                    
                    current_time = time.time()
                    
                    # Update packet statistics
                    self.packet_counts[src_ip].append(current_time)
                    
                    # Detect various threats
                    self._detect_threats(packet, src_ip, dst_ip)
                    
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
    
    def _detect_threats(self, packet, src_ip, dst_ip):
        """Detect various network threats"""
        # Port scanning detection
        if TCP in packet:
            tcp_layer = packet[TCP]
            self.port_scan_detector.analyze_packet(src_ip, dst_ip, tcp_layer.dport)
        
        # DDoS detection
        self.ddos_detector.analyze_packet(packet, src_ip, dst_ip)
        
        # Flood detection
        if TCP in packet:
            self.flood_detector.analyze_tcp_packet(packet, src_ip, dst_ip)
        elif UDP in packet:
            self.flood_detector.analyze_udp_packet(packet, src_ip, dst_ip)
        elif ICMP in packet:
            self.flood_detector.analyze_icmp_packet(packet, src_ip, dst_ip)
    
    def _analysis_loop(self):
        """Background analysis loop"""
        while self.is_monitoring:
            try:
                # Analyze collected data for patterns
                self._analyze_traffic_patterns()
                
                # Clean up old data
                self._cleanup_old_data()
                
                time.sleep(5)  # Analyze every 5 seconds
                
            except Exception as e:
                logging.error(f"Analysis loop error: {e}")
                time.sleep(10)
    
    def _analyze_traffic_patterns(self):
        """Analyze traffic patterns for anomalies"""
        current_time = time.time()
        time_window = 60  # 1 minute window
        
        for ip, timestamps in self.packet_counts.items():
            recent_packets = [ts for ts in timestamps if ts > current_time - time_window]
            packet_rate = len(recent_packets) / time_window
            
            # Check for high packet rates
            if packet_rate > self.config.alert_thresholds['tcp_flood']:
                threat = ThreatEvent(
                    id=0,
                    timestamp=datetime.now(),
                    threat_type="TCP_FLOOD",
                    source_ip=ip,
                    target_ip="Multiple",
                    severity="HIGH",
                    description=f"High TCP packet rate: {packet_rate:.2f} pps",
                    packet_count=len(recent_packets)
                )
                self.db_manager.log_threat(threat)
    
    def _cleanup_old_data(self):
        """Clean up old data from memory"""
        current_time = time.time()
        cleanup_threshold = 300  # 5 minutes
        
        for ip in list(self.packet_counts.keys()):
            self.packet_counts[ip] = deque(
                [ts for ts in self.packet_counts[ip] if ts > current_time - cleanup_threshold],
                maxlen=1000
            )

# =============================================================================
# THREAT DETECTORS
# =============================================================================

class PortScanDetector:
    """Port scanning detection engine"""
    
    def __init__(self, config: Config):
        self.config = config
        self.scan_attempts = defaultdict(lambda: defaultdict(list))
        self.window_size = 60  # 1 minute window
    
    def analyze_packet(self, src_ip: str, dst_ip: str, port: int):
        """Analyze packet for port scanning patterns"""
        try:
            current_time = time.time()
            
            # Add port attempt to history
            self.scan_attempts[src_ip][dst_ip].append((port, current_time))
            
            # Clean old attempts
            self._clean_old_attempts(src_ip, dst_ip, current_time)
            
            # Check for port scanning
            recent_attempts = self.scan_attempts[src_ip][dst_ip]
            unique_ports = len(set(port for port, _ in recent_attempts))
            
            if unique_ports > self.config.alert_thresholds['port_scan']:
                # Port scan detected
                threat = ThreatEvent(
                    id=0,
                    timestamp=datetime.now(),
                    threat_type="PORT_SCAN",
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    severity="MEDIUM",
                    description=f"Port scan detected: {unique_ports} unique ports",
                    packet_count=len(recent_attempts),
                    port=port
                )
                return threat
        
        except Exception as e:
            logging.error(f"Port scan detection error: {e}")
        
        return None
    
    def _clean_old_attempts(self, src_ip: str, dst_ip: str, current_time: float):
        """Clean old port scan attempts"""
        if src_ip in self.scan_attempts and dst_ip in self.scan_attempts[src_ip]:
            self.scan_attempts[src_ip][dst_ip] = [
                (port, ts) for port, ts in self.scan_attempts[src_ip][dst_ip]
                if ts > current_time - self.window_size
            ]

class DDoSDetector:
    """DDoS attack detection engine"""
    
    def __init__(self, config: Config):
        self.config = config
        self.source_counts = defaultdict(lambda: deque(maxlen=1000))
    
    def analyze_packet(self, packet, src_ip: str, dst_ip: str):
        """Analyze packet for DDoS patterns"""
        try:
            current_time = time.time()
            
            # Track sources contacting monitored IPs
            if dst_ip in self.config.monitored_ips:
                self.source_counts[dst_ip].append((src_ip, current_time))
                
                # Check for distributed source pattern
                recent_sources = [
                    source for source, ts in self.source_counts[dst_ip]
                    if ts > current_time - 60  # 1 minute window
                ]
                
                unique_sources = len(set(recent_sources))
                request_rate = len(recent_sources) / 60
                
                # DDoS detection logic
                if (unique_sources > 100 and request_rate > 500):
                    threat = ThreatEvent(
                        id=0,
                        timestamp=datetime.now(),
                        threat_type="DDoS_ATTEMPT",
                        source_ip="Multiple",
                        target_ip=dst_ip,
                        severity="HIGH",
                        description=f"DDoS attempt: {unique_sources} sources, {request_rate:.1f} rps",
                        packet_count=len(recent_sources)
                    )
                    return threat
        
        except Exception as e:
            logging.error(f"DDoS detection error: {e}")
        
        return None

class FloodDetector:
    """Flood attack detection engine"""
    
    def __init__(self, config: Config):
        self.config = config
        self.packet_rates = defaultdict(lambda: deque(maxlen=500))
    
    def analyze_tcp_packet(self, packet, src_ip: str, dst_ip: str):
        """Analyze TCP packet for flood patterns"""
        self._analyze_flood_pattern("TCP", src_ip, dst_ip)
    
    def analyze_udp_packet(self, packet, src_ip: str, dst_ip: str):
        """Analyze UDP packet for flood patterns"""
        self._analyze_flood_pattern("UDP", src_ip, dst_ip)
    
    def analyze_icmp_packet(self, packet, src_ip: str, dst_ip: str):
        """Analyze ICMP packet for flood patterns"""
        self._analyze_flood_pattern("ICMP", src_ip, dst_ip)
    
    def _analyze_flood_pattern(self, protocol: str, src_ip: str, dst_ip: str):
        """Analyze flood patterns for any protocol"""
        try:
            current_time = time.time()
            key = f"{protocol}_{src_ip}_{dst_ip}"
            
            self.packet_rates[key].append(current_time)
            
            # Calculate packet rate (last 10 seconds)
            recent_packets = [
                ts for ts in self.packet_rates[key]
                if ts > current_time - 10
            ]
            
            packet_rate = len(recent_packets) / 10
            
            # Check against thresholds
            threshold_key = f"{protocol.lower()}_flood"
            threshold = self.config.alert_thresholds.get(threshold_key, 1000)
            
            if packet_rate > threshold:
                threat = ThreatEvent(
                    id=0,
                    timestamp=datetime.now(),
                    threat_type=f"{protocol}_FLOOD",
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    severity="HIGH",
                    description=f"{protocol} flood detected: {packet_rate:.1f} pps",
                    packet_count=len(recent_packets),
                    protocol=protocol
                )
                return threat
        
        except Exception as e:
            logging.error(f"Flood detection error: {e}")
        
        return None

# =============================================================================
# PORT SCANNING ENGINE
# =============================================================================

class PortScanner:
    """Advanced port scanning capabilities"""
    
    def __init__(self, config: Config, db_manager: DatabaseManager):
        self.config = config
        self.db_manager = db_manager
        self.nm = nmap.PortScanner()
    
    def scan_ip(self, target_ip: str, port_range: str = "1-1000") -> List[PortScanResult]:
        """Perform standard port scan"""
        try:
            logging.info(f"Scanning {target_ip} on ports {port_range}")
            
            self.nm.scan(target_ip, port_range, arguments='-sS -T4')
            
            results = []
            for protocol in self.nm[target_ip].all_protocols():
                ports = self.nm[target_ip][protocol].keys()
                
                for port in ports:
                    port_data = self.nm[target_ip][protocol][port]
                    
                    result = PortScanResult(
                        ip_address=target_ip,
                        port=port,
                        protocol=protocol,
                        status=port_data['state'],
                        service=port_data.get('name', 'unknown'),
                        banner=port_data.get('product', '') + ' ' + port_data.get('version', ''),
                        timestamp=datetime.now()
                    )
                    results.append(result)
                    
                    # Save to database
                    self._save_scan_result(result)
            
            return results
            
        except Exception as e:
            logging.error(f"Port scan error: {e}")
            return []
    
    def deep_scan_ip(self, target_ip: str) -> List[PortScanResult]:
        """Perform deep port scan (all ports)"""
        return self.scan_ip(target_ip, "1-65535")
    
    def _save_scan_result(self, result: PortScanResult):
        """Save port scan result to database"""
        try:
            conn = sqlite3.connect(self.db_manager.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO port_scans 
                (timestamp, ip_address, port, protocol, status, service, banner)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                result.timestamp, result.ip_address, result.port, result.protocol,
                result.status, result.service, result.banner
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Error saving scan result: {e}")

# =============================================================================
# TELEGRAM BOT INTEGRATION
# =============================================================================

class TelegramBotManager:
    """Telegram bot management and communication"""
    
    def __init__(self, config: Config, network_monitor: NetworkMonitor):
        self.config = config
        self.network_monitor = network_monitor
        self.application = None
        self.bot = None
        
    async def start_bot(self):
        """Start the Telegram bot"""
        if not self.config.telegram_token:
            logging.error("Telegram token not configured")
            return False
        
        try:
            self.application = Application.builder().token(self.config.telegram_token).build()
            self.bot = Bot(token=self.config.telegram_token)
            
            # Register command handlers
            self._register_handlers()
            
            # Start polling
            await self.application.initialize()
            await self.application.start()
            await self.application.updater.start_polling()
            
            logging.info("Telegram bot started successfully")
            return True
            
        except Exception as e:
            logging.error(f"Error starting Telegram bot: {e}")
            return False
    
    def _register_handlers(self):
        """Register Telegram command handlers"""
        # Command handlers
        self.application.add_handler(CommandHandler("start", self._start_command))
        self.application.add_handler(CommandHandler("help", self._help_command))
        self.application.add_handler(CommandHandler("ping_ip", self._ping_ip_command))
        self.application.add_handler(CommandHandler("start_monitoring_ip", self._start_monitoring_command))
        self.application.add_handler(CommandHandler("location_ip", self._location_ip_command))
        self.application.add_handler(CommandHandler("stop", self._stop_command))
        self.application.add_handler(CommandHandler("view_threats", self._view_threats_command))
        self.application.add_handler(CommandHandler("add_ip", self._add_ip_command))
        self.application.add_handler(CommandHandler("remove_ip", self._remove_ip_command))
        self.application.add_handler(CommandHandler("scan_ip", self._scan_ip_command))
        self.application.add_handler(CommandHandler("deep_scan_ip", self._deep_scan_command))
        
        # Message handler for non-command messages
        self.application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, self._handle_message))
    
    async def _start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start command"""
        welcome_message = """
🚀 *Cyber Security Monitor Started*

*Available Commands:*
/help - Show all commands
/ping_ip [IP] - Ping an IP address
/start_monitoring_ip [IP] - Start monitoring IP
/location_ip [IP] - Get IP location
/stop - Stop monitoring
/view_threats - View recent threats
/add_ip [IP] - Add IP to monitor
/remove_ip [IP] - Remove IP from monitor
/scan_ip [IP] - Scan IP ports
/deep_scan_ip [IP] - Deep scan all ports

*Theme:* Purple Security 🛡️
        """
        await update.message.reply_text(welcome_message, parse_mode='Markdown')
    
    async def _help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /help command"""
        help_message = """
🛡️ *Cyber Security Monitor Help*

*Monitoring Commands:*
/start_monitoring_ip [IP] - Start monitoring IP for threats
/stop - Stop all monitoring
/view_threats - View recent security threats

*IP Analysis Commands:*
/ping_ip [IP] - Ping IP address
/location_ip [IP] - Get geographical location
/scan_ip [IP] - Scan common ports (1-1000)
/deep_scan_ip [IP] - Deep scan all ports (1-65535)

*IP Management Commands:*
/add_ip [IP] - Add IP to monitoring list
/remove_ip [IP] - Remove IP from monitoring list

*Threat Detection:*
- Port Scanning
- DDoS Attacks
- TCP/UDP Floods
- SYN Floods
- ICMP Floods
        """
        await update.message.reply_text(help_message, parse_mode='Markdown')
    
    async def _ping_ip_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /ping_ip command"""
        if not context.args:
            await update.message.reply_text("Usage: /ping_ip [IP_ADDRESS]")
            return
        
        ip_address = context.args[0]
        response = await self._ping_ip(ip_address)
        await update.message.reply_text(response)
    
    async def _start_monitoring_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /start_monitoring_ip command"""
        if not context.args:
            await update.message.reply_text("Usage: /start_monitoring_ip [IP_ADDRESS]")
            return
        
        ip_address = context.args[0]
        success = self.network_monitor.start_monitoring(ip_address)
        
        if success:
            await update.message.reply_text(f"✅ Started monitoring IP: {ip_address}")
        else:
            await update.message.reply_text(f"❌ Failed to start monitoring IP: {ip_address}")
    
    async def _location_ip_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /location_ip command"""
        if not context.args:
            await update.message.reply_text("Usage: /location_ip [IP_ADDRESS]")
            return
        
        ip_address = context.args[0]
        location_info = await self._get_ip_location(ip_address)
        await update.message.reply_text(location_info)
    
    async def _stop_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /stop command"""
        self.network_monitor.stop_monitoring()
        await update.message.reply_text("🛑 Monitoring stopped")
    
    async def _view_threats_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /view_threats command"""
        threats = self.network_monitor.db_manager.get_recent_threats(hours=24)
        
        if not threats:
            await update.message.reply_text("✅ No threats detected in the last 24 hours")
            return
        
        threat_message = "🚨 *Recent Threats (24h)*\n\n"
        for threat in threats[:10]:  # Show last 10 threats
            threat_message += f"*{threat.threat_type}* - {threat.source_ip}\n"
            threat_message += f"Target: {threat.target_ip} | Severity: {threat.severity}\n"
            threat_message += f"Time: {threat.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
            threat_message += f"Description: {threat.description}\n\n"
        
        await update.message.reply_text(threat_message, parse_mode='Markdown')
    
    async def _add_ip_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /add_ip command"""
        if not context.args:
            await update.message.reply_text("Usage: /add_ip [IP_ADDRESS]")
            return
        
        ip_address = context.args[0]
        self.config.monitored_ips.add(ip_address)
        self.config.save_config()
        await update.message.reply_text(f"✅ Added IP to monitoring: {ip_address}")
    
    async def _remove_ip_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /remove_ip command"""
        if not context.args:
            await update.message.reply_text("Usage: /remove_ip [IP_ADDRESS]")
            return
        
        ip_address = context.args[0]
        if ip_address in self.config.monitored_ips:
            self.config.monitored_ips.remove(ip_address)
            self.config.save_config()
            await update.message.reply_text(f"✅ Removed IP from monitoring: {ip_address}")
        else:
            await update.message.reply_text(f"❌ IP not in monitoring list: {ip_address}")
    
    async def _scan_ip_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /scan_ip command"""
        if not context.args:
            await update.message.reply_text("Usage: /scan_ip [IP_ADDRESS]")
            return
        
        ip_address = context.args[0]
        await update.message.reply_text(f"🔍 Scanning {ip_address}...")
        
        # This would be implemented with actual port scanning
        scan_results = "Scan functionality would be implemented here"
        await update.message.reply_text(scan_results)
    
    async def _deep_scan_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle /deep_scan_ip command"""
        if not context.args:
            await update.message.reply_text("Usage: /deep_scan_ip [IP_ADDRESS]")
            return
        
        ip_address = context.args[0]
        await update.message.reply_text(f"🔍 Deep scanning {ip_address} (all ports)...")
        
        # This would be implemented with actual deep port scanning
        scan_results = "Deep scan functionality would be implemented here"
        await update.message.reply_text(scan_results)
    
    async def _handle_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handle non-command messages"""
        await update.message.reply_text(
            "Type /help to see available commands",
            parse_mode='Markdown'
        )
    
    async def _ping_ip(self, ip_address: str) -> str:
        """Ping IP address"""
        try:
            param = "-n" if os.name == "nt" else "-c"
            command = ["ping", param, "4", ip_address]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                return f"✅ Ping successful to {ip_address}\n{result.stdout}"
            else:
                return f"❌ Ping failed to {ip_address}\n{result.stderr}"
        except Exception as e:
            return f"❌ Ping error: {str(e)}"
    
    async def _get_ip_location(self, ip_address: str) -> str:
        """Get IP address geographical location"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip_address}")
            data = response.json()
            
            if data['status'] == 'success':
                location_info = f"""
🌍 *Location for {ip_address}*

*Country:* {data.get('country', 'Unknown')}
*Region:* {data.get('regionName', 'Unknown')}
*City:* {data.get('city', 'Unknown')}
*ISP:* {data.get('isp', 'Unknown')}
*AS:* {data.get('as', 'Unknown')}
*Coordinates:* {data.get('lat', 'Unknown')}, {data.get('lon', 'Unknown')}
                """
                return location_info
            else:
                return f"❌ Could not get location for {ip_address}"
        except Exception as e:
            return f"❌ Location error: {str(e)}"
    
    async def send_alert(self, message: str):
        """Send alert message to Telegram"""
        if self.bot and self.config.telegram_chat_id:
            try:
                await self.bot.send_message(
                    chat_id=self.config.telegram_chat_id,
                    text=message,
                    parse_mode='Markdown'
                )
                return True
            except Exception as e:
                logging.error(f"Error sending Telegram alert: {e}")
        return False

# =============================================================================
# MAIN APPLICATION CLASS
# =============================================================================

class CyberSecurityMonitor:
    """Main cybersecurity monitoring application"""
    
    def __init__(self):
        self.config = Config()
        self.db_manager = DatabaseManager(self.config.db_file)
        self.network_monitor = NetworkMonitor(self.config, self.db_manager)
        self.port_scanner = PortScanner(self.config, self.db_manager)
        self.telegram_bot = TelegramBotManager(self.config, self.network_monitor)
        
        # Setup logging
        self._setup_logging()
        
        # Command history
        self.command_history = []
        
        # Telegram bot task
        self.bot_task = None
    
    def _setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config.log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
    
    async def start(self):
        """Start the cybersecurity monitor"""
        print(self._get_banner())
        print("🚀 Starting Advanced Cyber Security Monitor...")
        
        # Start Telegram bot
        if self.config.telegram_token:
            print("🤖 Starting Telegram bot...")
            await self.telegram_bot.start_bot()
        
        # Main loop
        await self._main_loop()
    
    def _get_banner(self):
        """Get application banner with purple theme"""
        banner = f"""
{self.config.purple_theme['primary']}
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║    CCURATE CYBER DEFENSE NETWORK MONTIRING ENGINE🛡️            ║
║                                                                ║
║    • Port Scanning Detection                                   ║
║    • DDoS Attack Monitoring                                    ║
║    • TCP/UDP Flood Detection                                   ║
║    • Real-time Threat Analysis                                 ║
║    • Telegram Bot Integration                                  ║
║    •                                                           ║
║                                                                ║
║    Community:https://github.com/Accurate-Cyber-Defense         ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
                                                                  
        """
        return banner
    
    async def _main_loop(self):
        """Main application loop"""
        print("\n💻 Type 'help' for available commands")
        
        while True:
            try:
                command = await asyncio.get_event_loop().run_in_executor(
                    None, input, f"\n{self.config.purple_theme['primary']}cyber-monitor> {self.config.purple_theme['text']}"
                )
                
                await self._process_command(command.strip())
                
            except KeyboardInterrupt:
                print("\n\n🛑 Shutting down...")
                await self._shutdown()
                break
            except EOFError:
                print("\n\n🛑 Shutting down...")
                await self._shutdown()
                break
            except Exception as e:
                logging.error(f"Main loop error: {e}")
    
    async def _process_command(self, command: str):
        """Process user commands"""
        if not command:
            return
        
        # Add to command history
        self.command_history.append(command)
        
        parts = command.split()
        cmd = parts[0].lower()
        args = parts[1:]
        
        try:
            if cmd == "help":
                self._show_help()
            elif cmd == "ping":
                await self._ping_ip(args)
            elif cmd == "start":
                await self._start_monitoring(args)
            elif cmd == "stop":
                self._stop_monitoring()
            elif cmd == "exit":
                await self._shutdown()
            elif cmd == "clear":
                self._clear_screen()
            elif cmd == "view_threats":
                self._view_threats(args)
            elif cmd == "add":
                await self._add_ip(args)
            elif cmd == "remove":
                await self._remove_ip(args)
            elif cmd == "location":
                await self._location_ip(args)
            elif cmd == "shutdown":
                await self._shutdown()
            elif cmd == "scan":
                await self._scan_ip(args)
            elif cmd == "deep_scan":
                await self._deep_scan_ip(args)
            elif cmd == "curl":
                await self._curl_domain(args)
            elif cmd == "config":
                await self._config_telegram(args)
            elif cmd == "test_telegram":
                await self._test_telegram()
            elif cmd == "export_telegram":
                await self._export_to_telegram()
            elif cmd == "generate_daily_report":
                await self._generate_report("daily")
            elif cmd == "generate_weekly_report":
                await self._generate_report("weekly")
            elif cmd == "generate_monthly_report":
                await self._generate_report("monthly")
            elif cmd == "history":
                self._show_history()
            else:
                print(f"❌ Unknown command: {cmd}. Type 'help' for available commands.")
        
        except Exception as e:
            logging.error(f"Command processing error: {e}")
            print(f"❌ Error executing command: {e}")
    
    def _show_help(self):
        """Show help information"""
        help_text = f"""
{self.config.purple_theme['primary']}
🛡️ Cyber Security Monitor - Available Commands
{self.config.purple_theme['text']}

📊 Monitoring Commands:
  start monitoring [IP]    - Start monitoring IP address
  stop                    - Stop monitoring
  view_threats           - View recent security threats

🌐 Network Commands:
  ping [IP]              - Ping IP address
  location [IP]          - Get IP geographical location
  scan [IP]              - Scan common ports (1-1000)
  deep_scan [IP]         - Deep scan all ports (1-65535)
  curl [DOMAIN]          - Curl domain information

🔧 Configuration Commands:
  config telegram [TOKEN] [CHAT_ID] - Configure Telegram
  test_telegram          - Test Telegram connection
  export_telegram        - Export data to Telegram

📈 Reporting Commands:
  generate_daily_report   - Generate daily security report
  generate_weekly_report  - Generate weekly security report
  generate_monthly_report - Generate monthly security report

🛠️ Utility Commands:
  add [IP]               - Add IP to monitoring list
  remove [IP]            - Remove IP from monitoring list
  clear                  - Clear screen
  history                - Show command history
  shutdown               - Shutdown application
  exit                   - Exit application
  help                   - Show this help message

💜 Purple Security Theme Active
        """
        print(help_text)
    
    async def _ping_ip(self, args: List[str]):
        """Ping IP address"""
        if len(args) < 1:
            print("Usage: ping [IP_ADDRESS]")
            return
        
        ip_address = args[0]
        response = await self.telegram_bot._ping_ip(ip_address)
        print(response)
    
    async def _start_monitoring(self, args: List[str]):
        """Start monitoring IP address"""
        if len(args) < 1:
            print("Usage: start monitoring [IP_ADDRESS]")
            return
        
        ip_address = args[0]
        success = self.network_monitor.start_monitoring(ip_address)
        
        if success:
            print(f"✅ Started monitoring IP: {ip_address}")
            
            # Send Telegram alert if configured
            if self.config.telegram_token and self.config.telegram_chat_id:
                await self.telegram_bot.send_alert(
                    f"🛡️ Started monitoring IP: `{ip_address}`"
                )
        else:
            print(f"❌ Failed to start monitoring IP: {ip_address}")
    
    def _stop_monitoring(self):
        """Stop monitoring"""
        self.network_monitor.stop_monitoring()
        print("🛑 Monitoring stopped")
    
    async def _shutdown(self):
        """Shutdown application"""
        print("🛑 Shutting down Cyber Security Monitor...")
        
        # Stop monitoring
        self.network_monitor.stop_monitoring()
        
        # Stop Telegram bot
        if self.telegram_bot.application:
            await self.telegram_bot.application.stop()
            await self.telegram_bot.application.shutdown()
        
        print("✅ Shutdown complete. Goodbye! 👋")
        sys.exit(0)
    
    def _clear_screen(self):
        """Clear terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        print(self._get_banner())
    
    def _view_threats(self, args: List[str]):
        """View recent threats"""
        hours = 24
        if args and args[0].isdigit():
            hours = int(args[0])
        
        threats = self.db_manager.get_recent_threats(hours=hours)
        
        if not threats:
            print(f"✅ No threats detected in the last {hours} hours")
            return
        
        print(f"🚨 Recent Threats (Last {hours} hours):")
        print("-" * 80)
        
        for threat in threats[:20]:  # Show last 20 threats
            print(f"Threat Type: {threat.threat_type}")
            print(f"Source IP: {threat.source_ip} -> Target IP: {threat.target_ip}")
            print(f"Severity: {threat.severity}")
            print(f"Time: {threat.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Description: {threat.description}")
            print(f"Packets: {threat.packet_count}")
            if threat.port:
                print(f"Port: {threat.port}")
            if threat.protocol:
                print(f"Protocol: {threat.protocol}")
            print("-" * 80)
    
    async def _add_ip(self, args: List[str]):
        """Add IP to monitoring list"""
        if len(args) < 1:
            print("Usage: add [IP_ADDRESS]")
            return
        
        ip_address = args[0]
        self.config.monitored_ips.add(ip_address)
        self.config.save_config()
        print(f"✅ Added IP to monitoring: {ip_address}")
    
    async def _remove_ip(self, args: List[str]):
        """Remove IP from monitoring list"""
        if len(args) < 1:
            print("Usage: remove [IP_ADDRESS]")
            return
        
        ip_address = args[0]
        if ip_address in self.config.monitored_ips:
            self.config.monitored_ips.remove(ip_address)
            self.config.save_config()
            print(f"✅ Removed IP from monitoring: {ip_address}")
        else:
            print(f"❌ IP not in monitoring list: {ip_address}")
    
    async def _location_ip(self, args: List[str]):
        """Get IP location"""
        if len(args) < 1:
            print("Usage: location [IP_ADDRESS]")
            return
        
        ip_address = args[0]
        location_info = await self.telegram_bot._get_ip_location(ip_address)
        print(location_info)
    
    async def _scan_ip(self, args: List[str]):
        """Scan IP ports"""
        if len(args) < 1:
            print("Usage: scan [IP_ADDRESS]")
            return
        
        ip_address = args[0]
        print(f"🔍 Scanning {ip_address}...")
        
        results = self.port_scanner.scan_ip(ip_address)
        
        if results:
            print(f"📊 Scan results for {ip_address}:")
            for result in results:
                print(f"Port {result.port}/{result.protocol} - {result.status} - {result.service}")
        else:
            print(f"❌ No open ports found or scan failed for {ip_address}")
    
    async def _deep_scan_ip(self, args: List[str]):
        """Deep scan IP all ports"""
        if len(args) < 1:
            print("Usage: deep_scan [IP_ADDRESS]")
            return
        
        ip_address = args[0]
        print(f"🔍 Deep scanning {ip_address} (all ports)...")
        
        results = self.port_scanner.deep_scan_ip(ip_address)
        
        if results:
            print(f"📊 Deep scan results for {ip_address}:")
            open_ports = [r for r in results if r.status == 'open']
            print(f"Found {len(open_ports)} open ports:")
            
            for result in open_ports[:50]:  # Show first 50 open ports
                print(f"Port {result.port}/{result.protocol} - {result.service}")
            
            if len(open_ports) > 50:
                print(f"... and {len(open_ports) - 50} more open ports")
        else:
            print(f"❌ No open ports found or scan failed for {ip_address}")
    
    async def _curl_domain(self, args: List[str]):
        """Curl domain information"""
        if len(args) < 1:
            print("Usage: curl [DOMAIN]")
            return
        
        domain = args[0]
        try:
            response = requests.get(f"http://{domain}", timeout=10)
            print(f"🌐 Curl results for {domain}:")
            print(f"Status Code: {response.status_code}")
            print(f"Headers: {dict(response.headers)}")
            print(f"Content Length: {len(response.content)} bytes")
        except Exception as e:
            print(f"❌ Curl error: {e}")
    
    async def _config_telegram(self, args: List[str]):
        """Configure Telegram settings"""
        if len(args) < 2:
            print("Usage: config telegram [TOKEN] [CHAT_ID]")
            return
        
        token = args[0]
        chat_id = args[1]
        
        self.config.telegram_token = token
        self.config.telegram_chat_id = chat_id
        self.config.save_config()
        
        print("✅ Telegram configuration updated")
        print(f"Token: {token[:10]}...")
        print(f"Chat ID: {chat_id}")
    
    async def _test_telegram(self):
        """Test Telegram connection"""
        if not self.config.telegram_token or not self.config.telegram_chat_id:
            print("❌ Telegram not configured. Use 'config telegram [TOKEN] [CHAT_ID]'")
            return
        
        print("🤖 Testing Telegram connection...")
        
        success = await self.telegram_bot.send_alert("🛡️ Cyber Security Monitor - Test Message")
        
        if success:
            print("✅ Telegram connection successful")
        else:
            print("❌ Telegram connection failed")
    
    async def _export_to_telegram(self):
        """Export data to Telegram"""
        if not self.config.telegram_token or not self.config.telegram_chat_id:
            print("❌ Telegram not configured")
            return
        
        print("📤 Exporting data to Telegram...")
        
        # Get recent threats
        threats = self.db_manager.get_recent_threats(hours=24)
        threat_count = len(threats)
        
        message = f"""
📊 *Cyber Security Monitor Export*

*Monitoring Statistics:*
• Monitored IPs: {len(self.config.monitored_ips)}
• Recent Threats (24h): {threat_count}
• Uptime: {datetime.now() - self.network_monitor.start_time}

*Recent Activity:*
"""
        
        if threats:
            for threat in threats[:5]:
                message += f"• {threat.threat_type} from {threat.source_ip}\n"
        else:
            message += "• No recent threats detected\n"
        
        message += "\n🛡️ *Purple Security System Active*"
        
        success = await self.telegram_bot.send_alert(message)
        
        if success:
            print("✅ Data exported to Telegram successfully")
        else:
            print("❌ Failed to export data to Telegram")
    
    async def _generate_report(self, report_type: str):
        """Generate security report"""
        print(f"📈 Generating {report_type} report...")
        
        # Calculate time range based on report type
        now = datetime.now()
        if report_type == "daily":
            start_time = now - timedelta(days=1)
        elif report_type == "weekly":
            start_time = now - timedelta(weeks=1)
        elif report_type == "monthly":
            start_time = now - timedelta(days=30)
        else:
            print(f"❌ Unknown report type: {report_type}")
            return
        
        # Get threats in time range
        threats = self.db_manager.get_recent_threats(hours=24 * (30 if report_type == "monthly" else 7 if report_type == "weekly" else 1))
        
        # Generate report
        report = f"""
🛡️ *Cyber Security {report_type.capitalize()} Report*
*Period:* {start_time.strftime('%Y-%m-%d')} to {now.strftime('%Y-%m-%d')}

*Summary Statistics:*
• Total Threats: {len(threats)}
• Monitored IPs: {len(self.config.monitored_ips)}
• Report Generated: {now.strftime('%Y-%m-%d %H:%M:%S')}

*Threat Breakdown:*
"""
        
        # Count threats by type
        threat_counts = {}
        for threat in threats:
            threat_type = threat.threat_type
            threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
        
        for threat_type, count in threat_counts.items():
            report += f"• {threat_type}: {count}\n"
        
        report += f"\n*Top Threat Sources:*\n"
        
        # Count threats by source IP
        source_counts = {}
        for threat in threats:
            source_ip = threat.source_ip
            source_counts[source_ip] = source_counts.get(source_ip, 0) + 1
        
        sorted_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)
        for source_ip, count in sorted_sources[:5]:
            report += f"• {source_ip}: {count} threats\n"
        
        report += f"\n💜 *Purple Security System Report*"
        
        print(report)
        
        # Save report to file
        filename = f"security_report_{report_type}_{now.strftime('%Y%m%d_%H%M%S')}.txt"
        with open(filename, 'w') as f:
            f.write(report)
        
        print(f"✅ Report saved to: {filename}")
    
    def _show_history(self):
        """Show command history"""
        print("📜 Command History:")
        for i, cmd in enumerate(self.command_history[-20:], 1):  # Show last 20 commands
            print(f"{i:3d}. {cmd}")

# =============================================================================
# APPLICATION STARTUP
# =============================================================================

async def main():
    """Main application entry point"""
    monitor = CyberSecurityMonitor()
    await monitor.start()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Application terminated by user")
    except Exception as e:
        logging.error(f"Application error: {e}")
        print(f"❌ Application error: {e}")