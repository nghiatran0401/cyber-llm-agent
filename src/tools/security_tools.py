"""
Purpose: Security tools the agent can use
Contains: Two tools
- parse_system_log() — reads log files and filters security-relevant entries
- fetch_cti_intelligence() — returns threat intelligence (mock database)

Also contains: LangChain Tool wrappers (log_parser, cti_fetch) so the agent can use them
What it does:
- Provides functions the agent can call
- Handles file operations, error handling
- Returns structured data for the agent
Use case: Tools that extend the agent’s capabilities
"""

from langchain_core.tools import Tool
from pathlib import Path
from src.config.settings import Settings
from src.utils.logger import setup_logger

logger = setup_logger(__name__)


def _resolve_safe_log_path(log_file_path: str) -> Path:
    """Resolve log path and prevent traversal outside approved directories."""
    raw_path = Path(log_file_path)
    candidate = raw_path if raw_path.is_absolute() else (Settings.LOGS_DIR / raw_path)
    resolved = candidate.resolve()
    allowed_root = Settings.LOGS_DIR.resolve()

    # Only allow reads under the configured logs directory.
    if allowed_root not in resolved.parents and resolved != allowed_root:
        raise ValueError("Invalid log file path. Access outside data/logs is not allowed.")

    if resolved.suffix.lower() not in Settings.ALLOWED_LOG_EXTENSIONS:
        raise ValueError(
            "Unsupported log file extension. "
            f"Allowed: {', '.join(sorted(Settings.ALLOWED_LOG_EXTENSIONS))}."
        )

    return resolved


def parse_system_log(log_file_path: str) -> str:
    """Parse system logs and extract relevant entries.
    
    Args:
        log_file_path: Path to the log file
        
    Returns:
        String containing relevant log entries (one per line)
    """
    try:
        log_path = _resolve_safe_log_path(log_file_path)

        if not log_path.exists():
            logger.warning(f"Log file not found: {log_path}")
            return "No log file found at the specified path."

        relevant_logs = []
        security_keywords = [
            'failed',
            'error',
            'unauthorized',
            'denied',
            'attack',
            'suspicious',
            'breach',
            'malware',
            'intrusion',
            'scan',
            'xss',
            'sql injection',
            'sqli',
            'brute force',
            'credential stuffing',
        ]
        
        with open(log_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line_lower = line.lower()
                if any(keyword in line_lower for keyword in security_keywords):
                    relevant_logs.append(f"Line {line_num}: {line.strip()}")
        
        if not relevant_logs:
            logger.info(f"No security-relevant entries found in {log_path}")
            return "No security-relevant entries found in the log file."
        
        result = "\n".join(relevant_logs)
        logger.info(f"Parsed {len(relevant_logs)} security-relevant entries from {log_path}")
        return result

    except ValueError as e:
        error_msg = str(e)
        logger.warning(error_msg)
        return f"Error: {error_msg}"
    except FileNotFoundError:
        error_msg = f"Log file not found: {log_file_path}"
        logger.error(error_msg)
        return error_msg
    except PermissionError:
        error_msg = f"Permission denied reading log file: {log_file_path}"
        logger.error(error_msg)
        return error_msg
    except Exception as e:
        error_msg = f"Error parsing log file: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return error_msg


def fetch_cti_intelligence(threat_type: str) -> str:
    """Fetch Cyber Threat Intelligence reports for a given threat type.
    
    This is a mock implementation. In production, integrate with real CTI APIs:
    - abuse.ch (MalwareBazaar, URLhaus)
    - AlienVault OTX
    - MISP (Malware Information Sharing Platform)
    - VirusTotal Intelligence
    
    Args:
        threat_type: Type of threat (e.g., "ransomware", "ddos", "phishing")
        
    Returns:
        CTI intelligence report as string
    """
    if not threat_type or not threat_type.strip():
        logger.warning("Empty threat type provided to CTI fetch")
        return "Error: Threat type cannot be empty."
    
    # Mock CTI database - replace with real API calls in production
    cti_db = {
        "ransomware": """Recent ransomware intelligence:
- LockBit 3.0: Active campaign targeting finance sector (2026)
- BlackCat/ALPHV: Increased activity in healthcare sector
- Ransomware-as-a-Service (RaaS) models on the rise
- Common vectors: Phishing emails, RDP brute force, unpatched vulnerabilities
Recommendation: Implement email filtering, disable RDP if not needed, patch systems regularly.""",
        
        "ddos": """DDoS threat intelligence:
- DDoS activity spike detected in region (2026)
- Common attack types: UDP floods, TCP SYN floods, HTTP floods
- Botnet infrastructure: Mirai variants, IoT devices compromised
- Peak attack volume: 500+ Gbps observed
Recommendation: Implement DDoS protection (Cloudflare, AWS Shield), rate limiting, traffic analysis.""",
        
        "phishing": """Phishing campaign intelligence:
- Active phishing campaign targeting energy sector (2026)
- Common techniques: Business Email Compromise (BEC), credential harvesting
- Targets: Office 365, Gmail, corporate SSO systems
- Indicators: Suspicious sender domains, urgency tactics, fake login pages
Recommendation: Enable MFA, user training, email security gateways, DMARC/SPF/DKIM.""",
        
        "brute force": """Brute force attack intelligence:
- SSH brute force attacks increasing globally
- Common targets: Port 22 (SSH), Port 3389 (RDP), Port 3306 (MySQL)
- Attack patterns: Dictionary attacks, credential stuffing
- Success rate: ~5% on weak passwords
Recommendation: Implement fail2ban, disable password auth (use keys), rate limiting, strong passwords.""",
        
        "malware": """Malware threat intelligence:
- Trojans: Emotet, TrickBot variants active
- RATs (Remote Access Trojans): Cobalt Strike, Metasploit
- Fileless malware: PowerShell-based attacks increasing
- Delivery methods: Email attachments, drive-by downloads, USB devices
Recommendation: Endpoint protection (EDR), application whitelisting, network segmentation."""
    }
    
    threat_lower = threat_type.lower().strip()
    result = cti_db.get(threat_lower, 
                       f"No specific threat intelligence found for '{threat_type}'. "
                       f"General recommendation: Monitor security logs, implement defense-in-depth, "
                       f"and maintain up-to-date threat intelligence feeds.")
    
    logger.info(f"CTI intelligence fetched for threat type: {threat_type}")
    return result


# Create LangChain tools
log_parser = Tool(
    name="LogParser",
    func=parse_system_log,
    description="Parses system logs and extracts security-relevant entries. "
                "Input should be a file path under data/logs/ (relative or absolute). "
                "Returns security-relevant log entries containing keywords like 'failed', 'error', 'unauthorized', etc."
)

cti_fetch = Tool(
    name="CTIFetch",
    func=fetch_cti_intelligence,
    description="Fetches Cyber Threat Intelligence reports for a given threat type. "
                "Input should be a threat type (e.g., 'ransomware', 'ddos', 'phishing', 'brute force', 'malware'). "
                "Returns intelligence report with recent threat information and recommendations."
)

