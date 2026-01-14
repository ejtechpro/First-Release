import sys
import os
import requests
import json
import time
import shutil
import subprocess
import socket
import hashlib
import re
import logging
import tempfile
import threading
from datetime import datetime, timedelta
from pathlib import Path
from functools import partial
import warnings
from dotenv import load_dotenv

# Suppress SSL warnings if needed
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

try:
    from PySide6.QtWidgets import (
        QApplication, QWidget, QLabel, QVBoxLayout, QTabWidget,
        QPushButton, QProgressBar, QHBoxLayout, QMessageBox,
        QDialog, QFormLayout, QCheckBox, QSpinBox, QDialogButtonBox,
        QFileDialog
    )
    from PySide6.QtCore import QThread, Signal, Qt, QTimer, QSettings, QMutex, QMutexLocker
    from PySide6.QtGui import QCloseEvent
except ImportError:
    print("PySide6 not found. Please install it: pip install PySide6")
    sys.exit(1)

# ============================================================================
# Configuration Constants
# ============================================================================

# Get the actual executable name
APP_NAME = os.path.basename(sys.executable) if hasattr(sys, 'frozen') else "hello.exe"
CURRENT_VERSION = "1.2.1"
VERSION_URL = "https://raw.githubusercontent.com/ejtechpro/First-Release/main/version.json"

# Security settings
VERIFY_SSL = True  # Set to False only for debugging
REQUIRE_SIGNATURE = False  # Set to True for production with proper signing
ALLOWED_DOWNLOAD_DOMAINS = ["github.com", "githubusercontent.com"]

# Platform-specific paths
if sys.platform == "win32":
    def get_app_data_path():
        """Get AppData/Local path for Windows"""
        appdata = os.getenv('LOCALAPPDATA')
        if appdata:
            app_dir = os.path.join(appdata, "HelloApp")
            os.makedirs(app_dir, exist_ok=True)
            return app_dir
        return os.path.dirname(sys.executable)
    
    APP_DATA_DIR = get_app_data_path()
else:
    # Linux/macOS
    APP_DATA_DIR = os.path.join(os.path.expanduser("~"), ".helloapp")
    os.makedirs(APP_DATA_DIR, exist_ok=True)

# Configuration files
CONFIG_FILE = os.path.join(APP_DATA_DIR, "config.json")
STATE_FILE = os.path.join(APP_DATA_DIR, "update_state.json")
PENDING_UPDATE_FILE = os.path.join(APP_DATA_DIR, "pending_update.json")
LAST_CHECK_FILE = os.path.join(APP_DATA_DIR, "last_check.json")
BACKUP_DIR = os.path.join(APP_DATA_DIR, "backups")
LOG_FILE = os.path.join(APP_DATA_DIR, "app.log")

# Setup logging
def setup_logging():
    """Configure logging to both file and console"""
    os.makedirs(APP_DATA_DIR, exist_ok=True)
    
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # File handler
    file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_format)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_format = logging.Formatter('%(levelname)s: %(message)s')
    console_handler.setFormatter(console_format)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

logger = setup_logging()

# ============================================================================
# Utility Functions
# ============================================================================

class FileLock:
    """Simple file-based lock for cross-process synchronization"""
    def __init__(self, lock_file):
        self.lock_file = lock_file
        self.lock_handle = None
        
    def acquire(self, timeout=10):
        """Acquire the lock with timeout"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                # Try to create lock file exclusively
                self.lock_handle = open(self.lock_file, 'x')
                return True
            except FileExistsError:
                time.sleep(0.1)
            except Exception as e:
                logger.error(f"Error acquiring lock: {e}")
                return False
        return False
    
    def release(self):
        """Release the lock"""
        if self.lock_handle:
            try:
                self.lock_handle.close()
                os.remove(self.lock_file)
            except Exception as e:
                logger.error(f"Error releasing lock: {e}")
            finally:
                self.lock_handle = None

def validate_version_format(version):
    """Ensure version string follows semantic versioning"""
    pattern = r'^\d+\.\d+\.\d+(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?(\+[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$'
    return bool(re.match(pattern, version))

def verify_file_hash(file_path, expected_hash, algorithm='sha256'):
    """Verify file integrity using hash"""
    try:
        if not os.path.exists(file_path):
            return False
            
        if algorithm == 'sha256':
            hasher = hashlib.sha256()
        elif algorithm == 'md5':
            hasher = hashlib.md5()
        else:
            logger.error(f"Unsupported hash algorithm: {algorithm}")
            return False
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        
        calculated_hash = hasher.hexdigest()
        return calculated_hash == expected_hash.lower()
    except Exception as e:
        logger.error(f"Hash verification failed: {e}")
        return False

def validate_url(url):
    """Validate download URL for security"""
    from urllib.parse import urlparse
    
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # Check against allowed domains
        domain = parsed.netloc.lower()
        if not any(allowed in domain for allowed in ALLOWED_DOWNLOAD_DOMAINS):
            logger.warning(f"Download from unauthorized domain: {domain}")
            return False
            
        return True
    except Exception as e:
        logger.error(f"URL validation failed: {e}")
        return False

def create_backup():
    """Create backup of current version before update"""
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"hello_backup_{CURRENT_VERSION}_{timestamp}.exe"
        backup_path = os.path.join(BACKUP_DIR, backup_name)
        
        # Copy current executable
        shutil.copy2(sys.executable, backup_path)
        
        # Clean old backups (keep last 5)
        backups = sorted(Path(BACKUP_DIR).glob("hello_backup_*.exe"))
        for old_backup in backups[:-5]:
            try:
                os.remove(old_backup)
            except Exception as e:
                logger.warning(f"Failed to clean old backup {old_backup}: {e}")
        
        logger.info(f"Backup created: {backup_path}")
        return backup_path
    except Exception as e:
        logger.error(f"Backup creation failed: {e}")
        return None

# ============================================================================
# Configuration Management
# ============================================================================

class Config:
    """Handles application configuration with thread safety"""
    
    DEFAULT_CONFIG = {
        "auto_check_enabled": True,
        "check_interval_hours": 24,
        "background_check": True,
        "notify_on_available": True,
        "max_retries": 3,
        "retry_delay_seconds": 5,
        "download_timeout": 30,
        "verify_ssl": VERIFY_SSL,
        "require_signature": REQUIRE_SIGNATURE
    }
    
    _mutex = QMutex()
    
    @staticmethod
    def load():
        """Load configuration from file with locking"""
        with QMutexLocker(Config._mutex):
            try:
                if os.path.exists(CONFIG_FILE):
                    with open(CONFIG_FILE, "r") as f:
                        config = json.load(f)
                    
                    # Merge with default config
                    for key, value in Config.DEFAULT_CONFIG.items():
                        if key not in config:
                            config[key] = value
                    
                    return config
            except Exception as e:
                logger.error(f"Error loading config: {e}")
            
            return Config.DEFAULT_CONFIG.copy()
    
    @staticmethod
    def save(config):
        """Save configuration to file with locking"""
        with QMutexLocker(Config._mutex):
            try:
                os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
                temp_file = CONFIG_FILE + ".tmp"
                with open(temp_file, "w") as f:
                    json.dump(config, f, indent=2, sort_keys=True)
                
                # Atomic replace
                if sys.platform == "win32":
                    os.replace(temp_file, CONFIG_FILE)
                else:
                    os.rename(temp_file, CONFIG_FILE)
                
                logger.info("Configuration saved")
                return True
            except Exception as e:
                logger.error(f"Error saving config: {e}")
                # Clean up temp file if exists
                try:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                except:
                    pass
                return False
    
    @staticmethod
    def update(key, value):
        """Update a specific config value"""
        config = Config.load()
        config[key] = value
        return Config.save(config)
    
    @staticmethod
    def should_check_for_updates():
        """Check if enough time has passed since last check"""
        try:
            config = Config.load()
            if not config.get("auto_check_enabled", True):
                return False
            
            if os.path.exists(LAST_CHECK_FILE):
                with open(LAST_CHECK_FILE, "r") as f:
                    last_check = json.load(f)
                
                last_check_time = datetime.fromisoformat(last_check.get("timestamp", "2000-01-01"))
                check_interval = config.get("check_interval_hours", 24)
                
                if datetime.now() - last_check_time < timedelta(hours=check_interval):
                    return False
        except Exception as e:
            logger.error(f"Error checking last update time: {e}")
        
        return True
    
    @staticmethod
    def update_last_check_time():
        """Update the last check timestamp"""
        try:
            last_check = {
                "timestamp": datetime.now().isoformat(),
                "version": CURRENT_VERSION
            }
            os.makedirs(os.path.dirname(LAST_CHECK_FILE), exist_ok=True)
            temp_file = LAST_CHECK_FILE + ".tmp"
            with open(temp_file, "w") as f:
                json.dump(last_check, f)
            
            # Atomic replace
            if sys.platform == "win32":
                os.replace(temp_file, LAST_CHECK_FILE)
            else:
                os.rename(temp_file, LAST_CHECK_FILE)
        except Exception as e:
            logger.error(f"Error updating last check time: {e}")

# ============================================================================
# Update Installer with Enhanced Security
# ============================================================================

class UpdateInstaller:
    """Handles installation of downloaded updates with security checks"""
    
    @staticmethod
    def check_pending_update():
        """Check if there's a pending update that needs to be applied"""
        try:
            if os.path.exists(PENDING_UPDATE_FILE):
                with open(PENDING_UPDATE_FILE, "r") as f:
                    pending = json.load(f)
                
                # Validate pending update
                if not all(k in pending for k in ["new_exe_path", "current_exe", "new_version"]):
                    logger.warning("Invalid pending update file, removing")
                    os.remove(PENDING_UPDATE_FILE)
                    return None
                
                # Check if file still exists
                if not os.path.exists(pending["new_exe_path"]):
                    logger.warning("Pending update file missing, removing")
                    os.remove(PENDING_UPDATE_FILE)
                    return None
                
                return pending
        except Exception as e:
            logger.error(f"Error checking pending update: {e}")
            # Clean up corrupted file
            try:
                if os.path.exists(PENDING_UPDATE_FILE):
                    os.remove(PENDING_UPDATE_FILE)
            except:
                pass
        return None
    
    @staticmethod
    def verify_update_file(file_path, expected_version=None):
        """Verify the update file before installation"""
        try:
            # Check file exists and has content
            if not os.path.exists(file_path):
                return False, "Update file does not exist"
            
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                return False, "Update file is empty"
            
            # Check if it's a valid executable (basic check)
            with open(file_path, 'rb') as f:
                header = f.read(2)
                if header != b'MZ' and header != b'#!':  # Windows PE or Unix shebang
                    # Could be a Python script or other format
                    logger.warning("Update file doesn't look like a standard executable")
            
            # TODO: Add signature verification here for production
            # if REQUIRE_SIGNATURE and not verify_signature(file_path):
            #     return False, "Invalid signature"
            
            return True, "Verification passed"
        except Exception as e:
            return False, f"Verification error: {e}"
    
    @staticmethod
    def install_update(new_exe_path, app_name, new_version, ask_permission=True):
        """
        Install the new version with security checks
        """
        try:
            # Verify update file first
            is_valid, message = UpdateInstaller.verify_update_file(new_exe_path, new_version)
            if not is_valid:
                logger.error(f"Update verification failed: {message}")
                QMessageBox.warning(None, "Update Failed", 
                                  f"Update verification failed:\n{message}")
                return False
            
            current_exe = sys.executable
            logger.info(f"Installing update from {new_exe_path} to {current_exe}")
            
            # Create backup before proceeding
            backup_path = create_backup()
            if backup_path:
                logger.info(f"Created backup at {backup_path}")
            
            # Ask user for permission if requested
            if ask_permission:
                reply = QMessageBox.question(
                    None,
                    "Update Ready",
                    f"Update to version {new_version} is ready to install.\n"
                    "The application needs to restart to complete the update.\n\n"
                    "A backup has been created in case of issues.\n\n"
                    "Restart now? (If you choose No, the update will be applied on next startup)",
                    QMessageBox.Yes | QMessageBox.No
                )
                
                if reply == QMessageBox.No:
                    # Save pending update for next startup
                    UpdateInstaller._save_pending_update(new_exe_path, current_exe, new_version)
                    QMessageBox.information(None, "Update Queued", 
                                          "Update has been queued for next startup.")
                    return True
            
            # Check if we're running from Program Files
            is_installed = False
            if sys.platform == "win32":
                program_files = os.getenv('ProgramFiles', 'C:\\Program Files')
                if current_exe.startswith(program_files):
                    is_installed = True
            
            # Choose installation method
            if is_installed:
                success = UpdateInstaller._install_for_installed_app(current_exe, new_exe_path, new_version)
            else:
                success = UpdateInstaller._install_for_portable_app(current_exe, new_exe_path, new_version)
            
            if success:
                logger.info(f"Successfully installed version {new_version}")
            else:
                logger.error(f"Failed to install version {new_version}")
                
                # Offer to restore from backup
                if backup_path and os.path.exists(backup_path):
                    reply = QMessageBox.question(
                        None,
                        "Update Failed",
                        "The update failed to install. Would you like to restore from backup?",
                        QMessageBox.Yes | QMessageBox.No
                    )
                    if reply == QMessageBox.Yes:
                        try:
                            shutil.copy2(backup_path, current_exe)
                            QMessageBox.information(None, "Restored", 
                                                  "Application has been restored from backup.")
                        except Exception as e:
                            logger.error(f"Restore failed: {e}")
            
            return success
            
        except Exception as e:
            logger.error(f"Update installation failed: {e}")
            QMessageBox.critical(None, "Update Error", 
                               f"An unexpected error occurred:\n{str(e)}")
            return False
    
    @staticmethod
    def _save_pending_update(new_exe_path, current_exe, new_version):
        """Save pending update information for next startup"""
        try:
            pending_info = {
                "new_exe_path": new_exe_path,
                "current_exe": current_exe,
                "new_version": new_version,
                "timestamp": time.time(),
                "backup_created": os.path.exists(BACKUP_DIR)
            }
            os.makedirs(os.path.dirname(PENDING_UPDATE_FILE), exist_ok=True)
            temp_file = PENDING_UPDATE_FILE + ".tmp"
            with open(temp_file, "w") as f:
                json.dump(pending_info, f, indent=2)
            
            # Atomic replace
            if sys.platform == "win32":
                os.replace(temp_file, PENDING_UPDATE_FILE)
            else:
                os.rename(temp_file, PENDING_UPDATE_FILE)
            
            logger.info(f"Saved pending update for version {new_version}")
        except Exception as e:
            logger.error(f"Failed to save pending update: {e}")
    
    @staticmethod
    def _install_for_portable_app(current_exe, temp_exe, new_version):
        """Install for portable/standalone app"""
        try:
            if sys.platform == "win32":
                return UpdateInstaller._create_windows_installer(current_exe, temp_exe, new_version)
            else:
                return UpdateInstaller._create_crossplatform_installer(current_exe, temp_exe, new_version)
        except Exception as e:
            logger.error(f"Portable install failed: {e}")
            return False
    
    @staticmethod
    def _create_windows_installer(current_exe, temp_exe, new_version):
        """Create Windows batch installer"""
        try:
            # Use a Python script instead of batch for better control
            installer_content = f'''import os
import time
import shutil
import sys
import subprocess
import json
import traceback

def main():
    current_exe = r"{current_exe}"
    temp_exe = r"{temp_exe}"
    new_version = "{new_version}"
    app_data_dir = r"{APP_DATA_DIR}"
    pending_file = os.path.join(app_data_dir, "pending_update.json")
    
    print(f"Installing update to version {{new_version}}...")
    
    # Wait for original process to exit
    time.sleep(3)
    
    max_retries = 10
    for attempt in range(max_retries):
        try:
            # Try to move/rename the current executable first
            if os.path.exists(current_exe):
                backup_name = current_exe + ".old"
                if os.path.exists(backup_name):
                    os.remove(backup_name)
                os.rename(current_exe, backup_name)
            
            # Move new executable into place
            shutil.move(temp_exe, current_exe)
            
            # Clean up old backup
            try:
                old_backup = current_exe + ".old"
                if os.path.exists(old_backup):
                    os.remove(old_backup)
            except:
                pass
            
            # Clean up pending update file
            if os.path.exists(pending_file):
                os.remove(pending_file)
            
            # Start the new version
            subprocess.Popen([current_exe], shell=True)
            print("Update successful!")
            break
            
        except PermissionError:
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
            else:
                print("Failed to update: Permission denied")
                # Try to restore from backup
                try:
                    if os.path.exists(backup_name):
                        shutil.move(backup_name, current_exe)
                except:
                    pass
                sys.exit(1)
        except Exception as e:
            print(f"Update failed: {{e}}")
            traceback.print_exc()
            sys.exit(1)
    
    # Clean up this script
    try:
        os.remove(__file__)
    except:
        pass

if __name__ == "__main__":
    main()
'''
            installer_file = os.path.join(APP_DATA_DIR, "update_installer.py")
            with open(installer_file, "w") as f:
                f.write(installer_content)
            
            # Start installer in a separate process
            subprocess.Popen([sys.executable, installer_file], 
                           creationflags=subprocess.CREATE_NO_WINDOW)
            return True
            
        except Exception as e:
            logger.error(f"Windows installer creation failed: {e}")
            return False
    
    @staticmethod
    def _create_crossplatform_installer(current_exe, temp_exe, new_version):
        """Cross-platform installation using Python"""
        try:
            installer_content = UpdateInstaller._get_installer_script(current_exe, temp_exe, new_version)
            installer_file = os.path.join(APP_DATA_DIR, "update_installer.py")
            with open(installer_file, "w") as f:
                f.write(installer_content)
            
            # Make executable on Unix
            if sys.platform != "win32":
                os.chmod(installer_file, 0o755)
            
            # Start installer
            subprocess.Popen([sys.executable, installer_file])
            return True
            
        except Exception as e:
            logger.error(f"Cross-platform installer failed: {e}")
            return False
    
    @staticmethod
    def _get_installer_script(current_exe, temp_exe, new_version):
        """Generate installer script content"""
        return f'''#!/usr/bin/env python3
import os
import time
import shutil
import sys
import subprocess
import json
import traceback

def main():
    current_exe = r"{current_exe}"
    temp_exe = r"{temp_exe}"
    new_version = "{new_version}"
    app_data_dir = r"{APP_DATA_DIR}"
    pending_file = os.path.join(app_data_dir, "pending_update.json")
    
    print(f"Installing update to version {{new_version}}...")
    
    # Wait for original process to exit
    time.sleep(3)
    
    max_retries = 10
    for attempt in range(max_retries):
        try:
            # Copy permissions from old file
            old_stat = None
            if os.path.exists(current_exe):
                old_stat = os.stat(current_exe)
            
            # Replace the file
            shutil.move(temp_exe, current_exe)
            
            # Restore permissions on Unix-like systems
            if old_stat and sys.platform != "win32":
                os.chmod(current_exe, old_stat.st_mode)
            
            # Clean up pending update file
            if os.path.exists(pending_file):
                os.remove(pending_file)
            
            # Clean up state file
            state_file = os.path.join(app_data_dir, "update_state.json")
            if os.path.exists(state_file):
                os.remove(state_file)
            
            # Start the new version
            if sys.platform == "win32":
                subprocess.Popen([current_exe], shell=True)
            else:
                subprocess.Popen([current_exe])
            
            print("Update successful!")
            break
            
        except PermissionError:
            if attempt < max_retries - 1:
                time.sleep(1)
                continue
            else:
                print("Failed to update: Permission denied")
                sys.exit(1)
        except Exception as e:
            print(f"Update failed: {{e}}")
            traceback.print_exc()
            sys.exit(1)
    
    # Clean up this script
    try:
        os.remove(__file__)
    except:
        pass

if __name__ == "__main__":
    main()
'''

# ============================================================================
# Update Thread with Enhanced Error Handling
# ============================================================================

class UpdateCheckThread(QThread):
    """Thread for checking updates with security validation"""
    update_found = Signal(str, str, dict)  # version, url, metadata
    check_complete = Signal(bool, str)
    no_update = Signal()
    
    def __init__(self, force_check=False):
        super().__init__()
        self.force_check = force_check
        self._stop_flag = False
    
    def run(self):
        try:
            if not self.force_check and not Config.should_check_for_updates():
                if self.force_check:
                    self.check_complete.emit(True, "Skipped - checked recently")
                return
            
            config = Config.load()
            verify_ssl = config.get("verify_ssl", VERIFY_SSL)
            
            logger.info(f"Checking for updates (SSL verify: {verify_ssl})")
            
            r = requests.get(VERSION_URL, timeout=10, verify=verify_ssl)
            r.raise_for_status()
            data = r.json()
            
            # Validate version data
            if not self._validate_version_data(data):
                self.check_complete.emit(False, "Invalid version data received")
                return
            
            latest = data["latest_version"]
            url = data["url"]
            
            # Validate URL
            if not validate_url(url):
                self.check_complete.emit(False, "Invalid download URL")
                return
            
            # Validate version format
            if not validate_version_format(latest):
                self.check_complete.emit(False, f"Invalid version format: {latest}")
                return
            
            # Update last check time
            Config.update_last_check_time()
            
            if latest != CURRENT_VERSION:
                metadata = {
                    "hash": data.get("sha256"),
                    "size": data.get("size"),
                    "release_notes": data.get("release_notes", "")
                }
                self.update_found.emit(latest, url, metadata)
                self.check_complete.emit(True, f"Update found: {latest}")
            else:
                self.no_update.emit()
                self.check_complete.emit(True, "Already up to date")
                
        except requests.exceptions.SSLError as e:
            error_msg = f"SSL error: {str(e)[:100]}"
            logger.error(error_msg)
            self.check_complete.emit(False, error_msg)
        except requests.exceptions.ConnectionError as e:
            error_msg = f"Connection error: {str(e)[:100]}"
            logger.error(error_msg)
            self.check_complete.emit(False, error_msg)
        except requests.exceptions.Timeout:
            error_msg = "Connection timeout"
            logger.error(error_msg)
            self.check_complete.emit(False, error_msg)
        except Exception as e:
            error_msg = f"Error: {str(e)[:100]}"
            logger.error(error_msg)
            self.check_complete.emit(False, error_msg)
    
    def _validate_version_data(self, data):
        """Validate the structure of version data"""
        required_keys = ["latest_version", "url"]
        for key in required_keys:
            if key not in data:
                logger.error(f"Missing required key in version data: {key}")
                return False
        return True
    
    def stop(self):
        """Stop the thread gracefully"""
        self._stop_flag = True
        self.quit()
        if not self.wait(2000):
            self.terminate()
            self.wait()


class UpdateThread(QThread):
    progress = Signal(int)
    finished = Signal(str, dict)  # file_path, metadata
    failed = Signal(str)
    retrying = Signal(int, str)
    hash_verification = Signal(bool, str)  # success, message
    
    def __init__(self, url, version, metadata=None, parent=None):
        super().__init__(parent)
        self.url = url
        self.version = version
        self.metadata = metadata or {}
        self._paused = False
        self._stop = False
        self.tmp_file = os.path.join(APP_DATA_DIR, f"hello_{version}.tmp")
        self.final_file = os.path.join(APP_DATA_DIR, f"hello_{version}.exe")
        
        config = Config.load()
        self.max_retries = config.get("max_retries", 3)
        self.retry_delay = config.get("retry_delay_seconds", 5)
        self.timeout = config.get("download_timeout", 30)
        self.verify_ssl = config.get("verify_ssl", VERIFY_SSL)
        
        self.file_lock = FileLock(os.path.join(APP_DATA_DIR, "download.lock"))
    
    def run(self):
        try:
            # Acquire file lock
            if not self.file_lock.acquire():
                self.failed.emit("Another download is in progress")
                return
            
            try:
                self._perform_download()
            finally:
                self.file_lock.release()
                
        except Exception as e:
            self.failed.emit(f"Download error: {str(e)}")
            logger.error(f"Download thread error: {e}", exc_info=True)
    
    def _perform_download(self):
        """Main download logic"""
        headers = {}
        start_byte = 0
        mode = "wb"
        file_path = self.tmp_file

        # Check for existing state
        state = self._load_state()
        if state and state.get("url") == self.url:
            file_path = state.get("file", self.tmp_file)
            downloaded = state.get("downloaded", 0)
            
            if os.path.exists(file_path):
                start_byte = downloaded
                headers = {"Range": f"bytes={start_byte}-"}
                mode = "ab"
                logger.info(f"Resuming download from byte {start_byte}")
            else:
                logger.warning("Download file missing, starting fresh")
                self._cleanup_state()
                start_byte = 0
                mode = "wb"
        
        # Download with retries
        for retry_count in range(self.max_retries + 1):
            try:
                self._download_chunks(file_path, headers, mode, start_byte)
                
                # Download completed successfully
                self._cleanup_state()
                
                # Verify hash if provided
                if self.metadata.get("hash"):
                    success, message = self._verify_download_hash(file_path)
                    self.hash_verification.emit(success, message)
                    if not success:
                        self.failed.emit(f"Hash verification failed: {message}")
                        return
                
                # Move to final location
                final_path = self._finalize_download(file_path)
                
                self.finished.emit(final_path, self.metadata)
                return
                
            except (requests.exceptions.ConnectionError, 
                    requests.exceptions.Timeout,
                    socket.gaierror) as e:
                
                if retry_count < self.max_retries:
                    self.retrying.emit(retry_count + 1, str(e))
                    
                    # Wait before retry
                    for i in range(self.retry_delay):
                        if self._stop:
                            return
                        time.sleep(1)
                    
                    continue
                else:
                    raise
            
            except Exception as e:
                raise
        
        # All retries failed
        raise requests.exceptions.ConnectionError("Max retries exceeded")
    
    def _download_chunks(self, file_path, headers, mode, start_byte):
        """Download file in chunks"""
        with requests.get(self.url, stream=True, timeout=self.timeout, 
                         headers=headers, verify=self.verify_ssl) as r:
            r.raise_for_status()
            
            # Handle resume
            if start_byte > 0 and r.status_code != 206:
                logger.warning("Server doesn't support resume, restarting")
                start_byte = 0
                mode = "wb"
                headers = {}
                r = requests.get(self.url, stream=True, timeout=self.timeout, 
                                verify=self.verify_ssl)
                r.raise_for_status()
            
            # Get total size
            total = 0
            if "content-range" in r.headers:
                content_range = r.headers["content-range"]
                total = int(content_range.split("/")[1])
            elif "content-length" in r.headers:
                total = int(r.headers.get("content-length", 0)) + start_byte
            
            downloaded = start_byte
            
            # Emit initial progress if resuming
            if start_byte > 0 and total > 0:
                self.progress.emit(int(downloaded / total * 100))
            
            # Save initial state
            self._save_state(downloaded, file_path, total)
            
            # Download chunks
            with open(file_path, mode) as f:
                chunk_size = 1024 * 1024  # 1MB
                for chunk in r.iter_content(chunk_size=chunk_size):
                    if self._stop:
                        self._save_state(downloaded, file_path, total)
                        return
                    
                    while self._paused:
                        time.sleep(0.2)
                    
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        # Save state periodically
                        if downloaded % (5 * 1024 * 1024) < len(chunk):
                            self._save_state(downloaded, file_path, total)
                        
                        if total > 0:
                            self.progress.emit(int(downloaded / total * 100))
            
            # Verify final size
            if total > 0 and downloaded != total:
                raise IOError(f"Download incomplete: {downloaded}/{total} bytes")
    
    def _verify_download_hash(self, file_path):
        """Verify downloaded file hash"""
        expected_hash = self.metadata.get("hash")
        if not expected_hash:
            return True, "No hash provided for verification"
        
        success = verify_file_hash(file_path, expected_hash)
        if success:
            return True, "Hash verification passed"
        else:
            return False, "Hash verification failed"
    
    def _finalize_download(self, temp_path):
        """Move temp file to final location"""
        if temp_path != self.final_file:
            shutil.move(temp_path, self.final_file)
        return self.final_file
    
    def _load_state(self):
        """Load download state"""
        try:
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE, "r") as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Error loading state: {e}")
        return None
    
    def _save_state(self, downloaded, file_path, total=0):
        """Save download state"""
        try:
            state = {
                "url": self.url,
                "version": self.version,
                "file": file_path,
                "downloaded": downloaded,
                "total_size": total,
                "timestamp": time.time()
            }
            os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
            temp_file = STATE_FILE + ".tmp"
            with open(temp_file, "w") as f:
                json.dump(state, f)
            
            # Atomic replace
            if sys.platform == "win32":
                os.replace(temp_file, STATE_FILE)
            else:
                os.rename(temp_file, STATE_FILE)
        except Exception as e:
            logger.error(f"Error saving state: {e}")
    
    def _cleanup_state(self):
        """Remove state file"""
        try:
            if os.path.exists(STATE_FILE):
                os.remove(STATE_FILE)
        except Exception:
            pass
    
    def pause(self):
        self._paused = True
    
    def resume(self):
        self._paused = False
    
    def stop(self):
        self._stop = True
        self.quit()
        if not self.wait(1000):
            self.terminate()
            self.wait()


# ============================================================================
# GUI Components
# ============================================================================

class HomeTab(QWidget):
    def __init__(self, parent_app):
        super().__init__()
        self.parent_app = parent_app
        self.download_callback = None
        self.setup_ui()
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Title and version
        self.label = QLabel(f"Hello there welcome to ejtech 👋\nVersion {CURRENT_VERSION}")
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(self.label)
        
        # Manual check button
        self.btn_check_now = QPushButton("🔍 Check for Updates Now")
        self.btn_check_now.clicked.connect(self.manual_check)
        layout.addWidget(self.btn_check_now)
        
        # Status label
        self.check_status = QLabel("")
        self.check_status.setAlignment(Qt.AlignCenter)
        self.check_status.setStyleSheet("color: gray; padding: 5px;")
        layout.addWidget(self.check_status)
        
        # Update notification area
        self.update_notice = QWidget()
        self.update_notice_layout = QHBoxLayout(self.update_notice)
        self.notice_label = QLabel("")
        self.btn_download = QPushButton("⬇ Download")
        self.btn_dismiss = QPushButton("❌")
        self.btn_download.hide()
        self.btn_dismiss.hide()
        self.update_notice_layout.addWidget(self.notice_label)
        self.update_notice_layout.addWidget(self.btn_download)
        self.update_notice_layout.addWidget(self.btn_dismiss)
        layout.addWidget(self.update_notice)
        
        # Connect signals
        self.btn_download.clicked.connect(self.on_download_clicked)
        self.btn_dismiss.clicked.connect(self.hide_update)
        
        layout.addStretch()
    
    def manual_check(self):
        """Manual check for updates"""
        self.btn_check_now.setEnabled(False)
        self.check_status.setText("Checking for updates...")
        self.parent_app.check_for_updates(force=True)
    
    def show_update(self, version, url, metadata, download_callback):
        """Show update available notification"""
        self.notice_label.setText(f"New version {version} available!")
        self.btn_download.show()
        self.btn_dismiss.show()
        self.download_callback = partial(download_callback, url, version, metadata)
    
    def on_download_clicked(self):
        """Handle download button click"""
        if self.download_callback:
            self.download_callback()
            self.hide_update()
    
    def hide_update(self):
        """Hide update notification"""
        self.notice_label.setText("")
        self.btn_download.hide()
        self.btn_dismiss.hide()
        self.btn_check_now.setEnabled(True)
        self.check_status.setText("")
        self.download_callback = None
    
    def update_check_status(self, message, is_success=True):
        """Update status label"""
        color = "green" if is_success else "red"
        self.check_status.setText(message)
        self.check_status.setStyleSheet(f"color: {color}; padding: 5px;")
        self.btn_check_now.setEnabled(True)
        
        if is_success:
            QTimer.singleShot(5000, lambda: self.check_status.setText(""))


class UpdateTab(QWidget):
    def __init__(self, parent_app):
        super().__init__()
        self.parent_app = parent_app
        self.thread = None
        self.latest_version = None
        self.download_url = None
        self.metadata = {}
        self.setup_ui()
        
        # Check for resumable downloads
        QTimer.singleShot(100, self.check_for_resume)
    
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Status label
        self.status_label = QLabel("No updates in progress")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        layout.addWidget(self.progress_bar)
        
        # Hash verification label
        self.hash_label = QLabel("")
        self.hash_label.setAlignment(Qt.AlignCenter)
        self.hash_label.setStyleSheet("color: blue;")
        layout.addWidget(self.hash_label)
        
        # Control buttons
        self.btn_pause = QPushButton("⏸ Pause")
        self.btn_resume = QPushButton("▶ Resume")
        self.btn_download = QPushButton("⬇ Download Update")
        self.btn_install = QPushButton("⚡ Install Now")
        self.btn_settings = QPushButton("⚙ Settings")
        self.btn_cleanup = QPushButton("🧹 Clean Up")
        
        self.btn_pause.setEnabled(False)
        self.btn_resume.setEnabled(False)
        self.btn_download.setEnabled(False)
        self.btn_install.setEnabled(False)
        self.btn_cleanup.setEnabled(True)
        
        # Button layouts
        top_layout = QHBoxLayout()
        top_layout.addWidget(self.btn_settings)
        top_layout.addStretch()
        top_layout.addWidget(self.btn_cleanup)
        
        main_layout = QHBoxLayout()
        main_layout.addWidget(self.btn_download)
        main_layout.addWidget(self.btn_pause)
        main_layout.addWidget(self.btn_resume)
        main_layout.addWidget(self.btn_install)
        
        layout.addLayout(top_layout)
        layout.addLayout(main_layout)
        layout.addStretch()
        
        # Connect signals
        self.btn_pause.clicked.connect(self.pause)
        self.btn_resume.clicked.connect(self.resume)
        self.btn_download.clicked.connect(self.start_download)
        self.btn_install.clicked.connect(self.install_update)
        self.btn_settings.clicked.connect(self.show_settings)
        self.btn_cleanup.clicked.connect(self.cleanup_files)
    
    def check_for_resume(self):
        """Check for resumable downloads on startup"""
        state = self.load_state()
        if state:
            self.update_progress_from_state(state)
            self.btn_download.setEnabled(True)
            self.btn_download.setText("Resume Download")
            self.latest_version = state.get("version")
            self.download_url = state.get("url")
    
    def load_state(self):
        """Load download state"""
        try:
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE, "r") as f:
                    state = json.load(f)
                
                # Validate state
                if not all(k in state for k in ["url", "version", "file", "downloaded"]):
                    logger.warning("Invalid state file")
                    self.cleanup_files()
                    return None
                
                # Check if file exists
                if not os.path.exists(state.get("file", "")):
                    logger.warning("Download file missing in state")
                    self.cleanup_files()
                    return None
                
                # Check if state is too old (more than 7 days)
                timestamp = state.get("timestamp", 0)
                if time.time() - timestamp > 604800:  # 7 days
                    logger.info("State file is too old, cleaning up")
                    self.cleanup_files()
                    return None
                
                return state
        except Exception as e:
            logger.error(f"Error loading state: {e}")
        
        return None
    
    def update_progress_from_state(self, state):
        """Update UI from saved state"""
        downloaded = state.get("downloaded", 0)
        total_size = state.get("total_size", 0)
        
        if total_size > 0:
            progress = int((downloaded / total_size) * 100)
            self.progress_bar.setValue(progress)
            
            downloaded_mb = downloaded / (1024 * 1024)
            total_mb = total_size / (1024 * 1024)
            
            self.status_label.setText(
                f"Resumable download: {progress}% ({downloaded_mb:.1f}/{total_mb:.1f} MB)"
            )
            return True
        
        return False
    
    def set_update_info(self, url, version, metadata):
        """Set update information"""
        self.download_url = url
        self.latest_version = version
        self.metadata = metadata
        
        # Check for existing download
        state = self.load_state()
        if state and state.get("url") == url:
            self.btn_download.setEnabled(True)
            self.btn_download.setText("Resume Download")
            self.update_progress_from_state(state)
        else:
            self.cleanup_files()
            self.btn_download.setEnabled(True)
            self.btn_download.setText("Download Update")
            self.progress_bar.setValue(0)
            self.status_label.setText(f"Update {version} ready to download")
    
    def start_download(self):
        """Start or resume download"""
        if not self.download_url or not self.latest_version:
            return
        
        self.btn_download.setEnabled(False)
        self.btn_pause.setEnabled(True)
        self.btn_resume.setEnabled(False)
        self.btn_install.setEnabled(False)
        
        self.status_label.setText(f"Downloading version {self.latest_version}...")
        
        # Create and start download thread
        self.thread = UpdateThread(self.download_url, self.latest_version, self.metadata)
        self.thread.progress.connect(self.progress_bar.setValue)
        self.thread.finished.connect(self.on_download_finished)
        self.thread.failed.connect(self.on_download_failed)
        self.thread.retrying.connect(self.on_retry)
        self.thread.hash_verification.connect(self.on_hash_verification)
        self.thread.start()
    
    def on_hash_verification(self, success, message):
        """Handle hash verification result"""
        if success:
            self.hash_label.setText("✓ Hash verified")
            self.hash_label.setStyleSheet("color: green;")
        else:
            self.hash_label.setText(f"⚠ {message}")
            self.hash_label.setStyleSheet("color: orange;")
    
    def on_retry(self, retry_count, error_message):
        """Handle retry attempts"""
        self.status_label.setText(
            f"Connection error. Retrying... ({retry_count}/3) - {error_message[:50]}..."
        )
    
    def pause(self):
        """Pause download"""
        if self.thread:
            self.thread.pause()
            self.status_label.setText(f"Download paused (v{self.latest_version})")
            self.btn_pause.setEnabled(False)
            self.btn_resume.setEnabled(True)
    
    def resume(self):
        """Resume download"""
        if self.thread:
            self.thread.resume()
            self.status_label.setText(f"Downloading version {self.latest_version}...")
            self.btn_pause.setEnabled(True)
            self.btn_resume.setEnabled(False)
    
    def on_download_finished(self, file_path, metadata):
        """Handle download completion"""
        self.status_label.setText(f"Download complete: {os.path.basename(file_path)}")
        self.progress_bar.setValue(100)
        self.btn_pause.setEnabled(False)
        self.btn_resume.setEnabled(False)
        self.btn_install.setEnabled(True)
        
        # Verify file
        is_valid, message = UpdateInstaller.verify_update_file(file_path)
        if is_valid:
            self.status_label.setText(f"Ready to install version {self.latest_version}")
        else:
            self.status_label.setText(f"Download completed but verification failed: {message}")
            QMessageBox.warning(self, "Verification Failed", 
                              f"The downloaded file failed verification:\n{message}")
    
    def install_update(self):
        """Install the downloaded update"""
        if not self.latest_version:
            return
        
        # Find the downloaded file
        pattern = os.path.join(APP_DATA_DIR, f"hello_{self.latest_version}.*")
        import glob
        files = glob.glob(pattern)
        
        if not files:
            QMessageBox.warning(self, "File Not Found", 
                              "Downloaded file not found. Please download again.")
            return
        
        file_path = files[0]
        
        # Install with permission prompt
        if UpdateInstaller.install_update(file_path, APP_NAME, self.latest_version, ask_permission=True):
            self.parent_app.close()
    
    def on_download_failed(self, error_msg):
        """Handle download failure"""
        self.status_label.setText(f"Download failed: {error_msg}")
        self.btn_pause.setEnabled(False)
        self.btn_resume.setEnabled(False)
        self.btn_download.setEnabled(True)
        self.btn_install.setEnabled(False)
        
        QMessageBox.warning(self, "Download Failed", 
                          f"Error: {error_msg}\n\nYou can try again later.")
    
    def show_settings(self):
        """Show update settings dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Update Settings")
        dialog.setMinimumWidth(400)
        
        layout = QFormLayout(dialog)
        
        config = Config.load()
        
        # Auto-check enabled
        cb_auto_check = QCheckBox()
        cb_auto_check.setChecked(config.get("auto_check_enabled", True))
        layout.addRow("Automatically check for updates:", cb_auto_check)
        
        # Check interval
        sb_interval = QSpinBox()
        sb_interval.setRange(1, 720)
        sb_interval.setValue(config.get("check_interval_hours", 24))
        sb_interval.setSuffix(" hours")
        layout.addRow("Check interval:", sb_interval)
        
        # Background check
        cb_background = QCheckBox()
        cb_background.setChecked(config.get("background_check", True))
        layout.addRow("Check in background:", cb_background)
        
        # Notify on update
        cb_notify = QCheckBox()
        cb_notify.setChecked(config.get("notify_on_available", True))
        layout.addRow("Notify when update available:", cb_notify)
        
        # Max retries
        sb_retries = QSpinBox()
        sb_retries.setRange(1, 10)
        sb_retries.setValue(config.get("max_retries", 3))
        layout.addRow("Maximum retries:", sb_retries)
        
        # Retry delay
        sb_delay = QSpinBox()
        sb_delay.setRange(1, 60)
        sb_delay.setValue(config.get("retry_delay_seconds", 5))
        sb_delay.setSuffix(" seconds")
        layout.addRow("Retry delay:", sb_delay)
        
        # SSL verification
        cb_ssl = QCheckBox()
        cb_ssl.setChecked(config.get("verify_ssl", VERIFY_SSL))
        layout.addRow("Verify SSL certificates:", cb_ssl)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        if dialog.exec() == QDialog.Accepted:
            new_config = {
                "auto_check_enabled": cb_auto_check.isChecked(),
                "check_interval_hours": sb_interval.value(),
                "background_check": cb_background.isChecked(),
                "notify_on_available": cb_notify.isChecked(),
                "max_retries": sb_retries.value(),
                "retry_delay_seconds": sb_delay.value(),
                "verify_ssl": cb_ssl.isChecked(),
                "require_signature": config.get("require_signature", REQUIRE_SIGNATURE)
            }
            
            if Config.save(new_config):
                QMessageBox.information(self, "Settings Saved", 
                                      "Update settings have been saved.")
    
    def cleanup_files(self):
        """Clean up temporary files"""
        try:
            files_to_remove = [
                STATE_FILE,
                os.path.join(APP_DATA_DIR, "hello_new.exe"),
                os.path.join(APP_DATA_DIR, "update_installer.py"),
                os.path.join(APP_DATA_DIR, "update_installer.bat"),
                os.path.join(APP_DATA_DIR, "download.lock")
            ]
            
            # Add temp files matching pattern
            import glob
            temp_files = glob.glob(os.path.join(APP_DATA_DIR, "hello_*.tmp"))
            temp_files += glob.glob(os.path.join(APP_DATA_DIR, "hello_*.exe"))
            files_to_remove.extend(temp_files)
            
            removed_count = 0
            for file_path in files_to_remove:
                try:
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        removed_count += 1
                        logger.info(f"Removed: {file_path}")
                except Exception as e:
                    logger.warning(f"Failed to remove {file_path}: {e}")
            
            self.status_label.setText(f"Cleaned up {removed_count} files")
            self.progress_bar.setValue(0)
            self.btn_download.setEnabled(False)
            self.btn_install.setEnabled(False)
            
            QTimer.singleShot(3000, lambda: self.status_label.setText("Ready"))
            
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            QMessageBox.warning(self, "Cleanup Error", 
                              f"Error during cleanup: {str(e)}")


class HelloApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_app()
        
        # Start initial checks
        QTimer.singleShot(100, self.on_startup)
    
    def setup_app(self):
        """Setup application UI"""
        self.setWindowTitle("Hello App")
        self.resize(500, 350)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        self.tabs = QTabWidget()
        self.home_tab = HomeTab(self)
        self.update_tab = UpdateTab(self)
        
        self.tabs.addTab(self.home_tab, "🏠 Home")
        self.tabs.addTab(self.update_tab, "🔄 Update")
        
        layout.addWidget(self.tabs)
        
        # Initialize threads and timers
        self.update_check_thread = None
        self.background_timer = QTimer()
        self.background_timer.timeout.connect(self.background_check)
    
    def on_startup(self):
        """Handle startup checks"""
        logger.info(f"Application starting (v{CURRENT_VERSION})")
        
        # Check for pending updates
        pending_update = UpdateInstaller.check_pending_update()
        if pending_update:
            self.handle_pending_update(pending_update)
        
        # Check for existing download state
        state = self.update_tab.load_state()
        if state:
            self.update_tab.update_progress_from_state(state)
            self.tabs.setCurrentIndex(1)
        
        # Perform initial update check
        self.check_for_updates(force=False)
        
        # Start background timer
        config = Config.load()
        if config.get("background_check", True):
            interval_hours = config.get("check_interval_hours", 24)
            interval_ms = interval_hours * 60 * 60 * 1000
            self.background_timer.start(interval_ms)
            logger.info(f"Background check enabled (every {interval_hours} hours)")
    
    def handle_pending_update(self, pending_update):
        """Handle pending update from previous session"""
        reply = QMessageBox.question(
            self,
            "Pending Update",
            f"An update to version {pending_update.get('new_version', 'unknown')} "
            "was downloaded but not installed.\n\n"
            "Would you like to install it now?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            if UpdateInstaller.install_update(
                pending_update["new_exe_path"],
                APP_NAME,
                pending_update["new_version"],
                ask_permission=False
            ):
                self.close()
        else:
            # Clean up pending update if user declines
            try:
                if os.path.exists(PENDING_UPDATE_FILE):
                    os.remove(PENDING_UPDATE_FILE)
            except Exception as e:
                logger.error(f"Failed to remove pending update file: {e}")
    
    def check_for_updates(self, force=False):
        """Check for updates"""
        config = Config.load()
        
        if not force and not Config.should_check_for_updates():
            if force:
                self.home_tab.update_check_status("Skipped - checked recently", True)
            return
        
        # Stop existing thread if running
        if self.update_check_thread and self.update_check_thread.isRunning():
            self.update_check_thread.stop()
        
        # Start new check thread
        self.update_check_thread = UpdateCheckThread(force_check=force)
        self.update_check_thread.update_found.connect(self.on_update_found)
        self.update_check_thread.no_update.connect(self.on_no_update)
        self.update_check_thread.check_complete.connect(self.on_check_complete)
        self.update_check_thread.start()
    
    def background_check(self):
        """Background update check"""
        config = Config.load()
        if config.get("background_check", True):
            self.check_for_updates(force=False)
    
    def on_update_found(self, version, url, metadata):
        """Handle update found"""
        config = Config.load()
        
        # Update UI
        download_callback = lambda url, ver, meta: self.update_tab.start_download()
        self.home_tab.show_update(version, url, metadata, download_callback)
        self.update_tab.set_update_info(url, version, metadata)
        
        # Switch to update tab if app is not focused
        if not QApplication.activeWindow():
            self.tabs.setCurrentIndex(1)
        
        # Show notification
        if config.get("notify_on_available", True):
            self.home_tab.update_check_status(f"Update {version} available!", True)
            
            # System notification could be added here
            # e.g., using plyer or system tray notification
    
    def on_no_update(self):
        """Handle no update found"""
        # Only log, no UI update needed for background checks
        logger.info("No update available")
    
    def on_check_complete(self, success, message):
        """Handle check completion"""
        # Update manual check status
        self.home_tab.update_check_status(message, success)
        
        # Update last check time
        if success:
            Config.update_last_check_time()
    
    def closeEvent(self, event):
        """Handle application closure"""
        logger.info("Application closing")
        
        # Stop timers
        self.background_timer.stop()
        
        # Stop threads gracefully
        if self.update_check_thread and self.update_check_thread.isRunning():
            self.update_check_thread.stop()
        
        if hasattr(self.update_tab, 'thread') and self.update_tab.thread and self.update_tab.thread.isRunning():
            reply = QMessageBox.question(
                self, "Download in Progress",
                "A download is in progress. It will be saved and can be resumed later.\n"
                "Do you want to close the application?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                # Save state before closing
                if self.update_tab.thread:
                    self.update_tab.thread.pause()
                    # Give thread time to save state
                    QTimer.singleShot(200, lambda: event.accept())
                else:
                    event.accept()
            else:
                event.ignore()
        else:
            event.accept()


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main application entry point"""
    try:
        # Create application instance
        app = QApplication(sys.argv)
        app.setApplicationName("Hello App")
        app.setOrganizationName("HelloOrg")
        
        # Create and show main window
        window = HelloApp()
        window.show()
        
        # Start application
        return app.exec()
        
    except Exception as e:
        logger.critical(f"Application failed to start: {e}", exc_info=True)
        QMessageBox.critical(None, "Fatal Error", 
                           f"Application failed to start:\n{str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())