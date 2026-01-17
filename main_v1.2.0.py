import sys
import os
import requests
import json
import time
import shutil
import subprocess
import socket
from datetime import datetime, timedelta
from pathlib import Path 

from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QTabWidget,
    QPushButton, QProgressBar, QHBoxLayout, QMessageBox
)
from PySide6.QtCore import QThread, Signal, Qt, QTimer, QSettings

# Get the actual executable name from sys.argv[0]
APP_NAME = os.path.basename(sys.executable) if hasattr(sys, 'frozen') else "innoselfupdate.exe"
CURRENT_VERSION = "1.2.0"
VERSION_URL = "https://raw.githubusercontent.com/ejtechpro/inno-self-update-setup/main/version.json"


# Platform-specific paths
if sys.platform == "win32":
    def get_app_data_path():
        """Get AppData/Local path for Windows"""
        appdata = os.getenv('LOCALAPPDATA')
        if appdata:
            app_dir = os.path.join(appdata, "InnoSelfUpdate")
            os.makedirs(app_dir, exist_ok=True)
            return app_dir
        return os.path.dirname(sys.executable)
    
    APP_DATA_DIR = get_app_data_path()
else:
    # Linux/macOS
    APP_DATA_DIR = os.path.join(os.path.expanduser("~"), ".innoselfupdateapp")
    os.makedirs(APP_DATA_DIR, exist_ok=True)

# Configuration file
CONFIG_FILE = os.path.join(APP_DATA_DIR, "config.json")
# State and temp files in user data directory
STATE_FILE = os.path.join(APP_DATA_DIR, "update_state.json")
PENDING_UPDATE_FILE = os.path.join(APP_DATA_DIR, "pending_update.json")
LAST_CHECK_FILE = os.path.join(APP_DATA_DIR, "last_check.json")



class Config:
    """Handles application configuration"""
    
    DEFAULT_CONFIG = {
        "auto_check_enabled": True,
        "check_interval_hours": 24,  # Check once per day by default
        "background_check": True,
        "notify_on_available": True
    }
    
    @staticmethod
    def load():
        """Load configuration from file"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r") as f:
                    config = json.load(f)
                # Merge with default config to ensure all keys exist
                for key, value in Config.DEFAULT_CONFIG.items():
                    if key not in config:
                        config[key] = value
                return config
        except Exception as e:
            print(f"Error loading config: {e}")
        
        # Return default config if file doesn't exist or error
        return Config.DEFAULT_CONFIG.copy()
    
    @staticmethod
    def save(config):
        """Save configuration to file"""
        try:
            os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
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
                
                # Check if enough hours have passed
                if datetime.now() - last_check_time < timedelta(hours=check_interval):
                    return False
        except Exception as e:
            print(f"Error checking last update time: {e}")
        
        return True
    
    @staticmethod
    def update_last_check_time():
        """Update the last check timestamp"""
        try:
            last_check = {
                "timestamp": datetime.now().isoformat()
            }
            os.makedirs(os.path.dirname(LAST_CHECK_FILE), exist_ok=True)
            with open(LAST_CHECK_FILE, "w") as f:
                json.dump(last_check, f)
        except Exception as e:
            print(f"Error updating last check time: {e}")


class UpdateInstaller:
    """Handles the installation of downloaded updates"""
    
    @staticmethod
    def check_pending_update():
        """Check if there's a pending update that needs to be applied"""
        try:
            if os.path.exists(PENDING_UPDATE_FILE):
                with open(PENDING_UPDATE_FILE, "r") as f:
                    return json.load(f)
        except Exception:
            pass
        return None
    
    @staticmethod
    def install_update(new_exe_path, app_name, new_version, ask_permission=True):
        """
        Install the new version by replacing the old executable
        and restarting the application.
        
        If ask_permission is True, will prompt user before restarting.
        If user refuses, the update will be applied on next startup.
        """
        try:
            current_exe = sys.executable
            temp_exe = new_exe_path
            
            print(f"Current executable: {current_exe}")
            print(f"New executable: {temp_exe}")
            print(f"New version: {new_version}")
            
            # Check if we're running from Program Files (installed version)
            is_installed = False
            if sys.platform == "win32":
                program_files = os.getenv('ProgramFiles', 'C:\\Program Files')
                if current_exe.startswith(program_files):
                    is_installed = True
                    print("Running from Program Files - needs admin rights")
            
            # Ask user for permission to restart if requested
            if ask_permission:
                reply = QMessageBox.question(
                    None,  # Will be set by caller
                    "Update Ready",
                    f"Update to version {new_version} is ready to install.\n"
                    "The application needs to restart to complete the update.\n\n"
                    "Restart now? (If you choose No, the update will be applied on next startup)",
                    QMessageBox.Yes | QMessageBox.No
                )
                
                if reply == QMessageBox.No:
                    # Save pending update for next startup
                    UpdateInstaller._save_pending_update(new_exe_path, current_exe, new_version)
                    return True  # User declined, but update is queued
            
            # For installed apps, we need a different approach
            if is_installed:
                return UpdateInstaller._install_for_installed_app(current_exe, temp_exe, new_version)
            else:
                return UpdateInstaller._install_for_portable_app(current_exe, temp_exe, new_version)
            
        except Exception as e:
            print(f"Update installation failed: {e}")
            return False
    
    @staticmethod
    def _save_pending_update(new_exe_path, current_exe, new_version):
        """Save pending update information for next startup"""
        try:
            pending_info = {
                "new_exe_path": new_exe_path,
                "current_exe": current_exe,
                "new_version": new_version,
                "timestamp": time.time()
            }
            os.makedirs(os.path.dirname(PENDING_UPDATE_FILE), exist_ok=True)
            with open(PENDING_UPDATE_FILE, "w") as f:
                json.dump(pending_info, f)
            print(f"Saved pending update for version {new_version}")
        except Exception as e:
            print(f"Failed to save pending update: {e}")
    
    @staticmethod
    def _install_for_portable_app(current_exe, temp_exe, new_version):
        """Install for portable/standalone app"""
        try:
            # Create a batch file for Windows
            if sys.platform == "win32":
                batch_content = f"""@echo off
echo Updating to version {new_version}...
timeout /t 2 /nobreak >nul

:retry
del "{current_exe}" 2>nul
if exist "{current_exe}" (
    timeout /t 1 /nobreak >nul
    goto retry
)

move "{temp_exe}" "{current_exe}" 2>nul
if not exist "{current_exe}" (
    copy "{temp_exe}" "{current_exe}" 2>nul
)

start "" "{current_exe}"
del "%~f0"
"""
                batch_file = os.path.join(APP_DATA_DIR, "update_installer.bat")
                with open(batch_file, "w") as f:
                    f.write(batch_content)
                
                subprocess.Popen([batch_file], shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
                return True
            else:
                # For non-Windows, use Python script
                return UpdateInstaller._install_with_python_script(current_exe, temp_exe, new_version)
                
        except Exception as e:
            print(f"Portable install failed: {e}")
            return False
    
    @staticmethod
    def _install_with_python_script(current_exe, temp_exe, new_version):
        """Cross-platform installation using Python"""
        try:
            # Create a Python installer script
            installer_script = f'''import os
import time
import shutil
import sys
import subprocess
import json

current_exe = r"{current_exe}"
temp_exe = r"{temp_exe}"
new_version = "{new_version}"

print(f"Updating {{current_exe}} to version {{new_version}}...")

# Wait for original process to exit
time.sleep(2)

max_retries = 10
for i in range(max_retries):
    try:
        # Try to delete old executable
        if os.path.exists(current_exe):
            os.remove(current_exe)
        
        # Move new executable into place
        shutil.move(temp_exe, current_exe)
        
        # Make executable on Unix-like systems
        if sys.platform != "win32":
            os.chmod(current_exe, 0o755)
        
        # Clean up pending update file
        pending_file = os.path.join(os.path.dirname(r"{APP_DATA_DIR}"), "pending_update.json")
        if os.path.exists(pending_file):
            os.remove(pending_file)
        
        # Start the new version
        subprocess.Popen([current_exe])
        print("Update successful!")
        break
    except PermissionError:
        if i < max_retries - 1:
            time.sleep(1)
            continue
        else:
            print("Failed to update: Could not replace executable")
            sys.exit(1)
    except Exception as e:
        print(f"Update failed: {{e}}")
        sys.exit(1)

# Clean up this script
try:
    os.remove(__file__)
except:
    pass
'''
            installer_file = os.path.join(APP_DATA_DIR, "update_installer.py")
            with open(installer_file, "w") as f:
                f.write(installer_script)
            
            # Start installer in a separate process
            subprocess.Popen([sys.executable, installer_file])
            return True
            
        except Exception as e:
            print(f"Python installer failed: {e}")
            return False


class UpdateCheckThread(QThread):
    """Thread for checking updates in background"""
    update_found = Signal(str, str)  # version, url
    check_complete = Signal(bool, str)  # success, message
    no_update = Signal()
    
    def __init__(self, force_check=False):
        super().__init__()
        self.force_check = force_check
    
    def run(self):
        try:
            # Check if we should perform the check
            if not self.force_check and not Config.should_check_for_updates():
                self.check_complete.emit(True, "Skipped - too soon since last check")
                return
            
            r = requests.get(VERSION_URL, timeout=10)
            r.raise_for_status()
            data = r.json()
            latest = data["latest_version"]
            url = data["url"]
            
            # Update last check time
            Config.update_last_check_time()
            
            if latest != CURRENT_VERSION:
                self.update_found.emit(latest, url)
                self.check_complete.emit(True, f"Update found: {latest}")
            else:
                self.no_update.emit()
                self.check_complete.emit(True, "Already up to date")
                
        except requests.exceptions.ConnectionError as e:
            self.check_complete.emit(False, f"Connection error: {str(e)[:100]}")
        except requests.exceptions.Timeout:
            self.check_complete.emit(False, "Connection timeout")
        except Exception as e:
            self.check_complete.emit(False, f"Error: {str(e)[:100]}")


class UpdateThread(QThread):
    progress = Signal(int)
    finished = Signal(str)
    failed = Signal(str)
    retrying = Signal(int, str)  # retry_count, error_message

    def __init__(self, url, version, parent=None):
        super().__init__(parent)
        self.url = url
        self.version = version
        self._paused = False
        self._stop = False
        # Store temp file in user data directory
        self.tmp_file = os.path.join(APP_DATA_DIR, f"innoselfupdate_v{CURRENT_VERSION}.exe")
        self.max_retries = 3
        self.retry_delay = 5  # seconds

    def run(self):
        try:
            headers = {}
            start_byte = 0
            mode = "wb"

            # Check if we can resume from state file
            state = self._load_state()
            if state and state.get("url") == self.url:
                file_path = state.get("file", self.tmp_file)
                downloaded = state.get("downloaded", 0)
                
                if os.path.exists(file_path):
                    start_byte = downloaded
                    headers = {"Range": f"bytes={start_byte}-"}
                    mode = "ab"
                    print(f"Resuming download from byte {start_byte}")
                else:
                    # File was deleted but state exists - start from beginning
                    print("Download file missing, starting from beginning")
                    self._cleanup_state()  # Clean up invalid state
                    start_byte = 0
                    mode = "wb"
            
            # Try with retries
            for retry_count in range(self.max_retries + 1):
                try:
                    r = requests.get(self.url, stream=True, timeout=30, headers=headers)
                    
                    # Handle 206 Partial Content for resume
                    if start_byte > 0 and r.status_code != 206:
                        print("Server doesn't support resume, starting from beginning")
                        start_byte = 0
                        mode = "wb"
                        headers = {}
                        r = requests.get(self.url, stream=True, timeout=30)

                    r.raise_for_status()
                    
                    # Get total size
                    total = 0
                    if "content-range" in r.headers:
                        # Parse content-range: bytes start-end/total
                        content_range = r.headers["content-range"]
                        total = int(content_range.split("/")[1])
                    elif "content-length" in r.headers:
                        total = int(r.headers.get("content-length", 0)) + start_byte
                    else:
                        total = 0

                    downloaded = start_byte
                    
                    # If we're resuming, emit current progress immediately
                    if start_byte > 0 and total > 0:
                        self.progress.emit(int(downloaded / total * 100))
                    
                    # Save initial state with total size if we know it
                    self._save_state(downloaded, self.tmp_file, self.url, self.version, total)
                    
                    with open(self.tmp_file, mode) as f:
                        for chunk in r.iter_content(chunk_size=1024 * 1024):  # 1MB chunks
                            if self._stop:
                                self._save_state(downloaded, self.tmp_file, self.url, self.version, total)
                                return
                            
                            while self._paused:
                                self.msleep(200)
                            
                            if chunk:
                                f.write(chunk)
                                downloaded += len(chunk)
                                
                                # Save state periodically
                                if downloaded % (5 * 1024 * 1024) < len(chunk):  # Every ~5MB
                                    self._save_state(downloaded, self.tmp_file, self.url, self.version, total)
                                
                                if total > 0:
                                    self.progress.emit(int(downloaded / total * 100))
                    
                    # Download complete - remove state file
                    self._cleanup_state()
                    
                    # Verify file size if possible
                    if total > 0 and downloaded != total:
                        self.failed.emit(f"Download incomplete: {downloaded}/{total} bytes")
                        return
                    
                    self.finished.emit(self.tmp_file)
                    return  # Success, exit retry loop
                    
                except (requests.exceptions.ConnectionError, 
                        requests.exceptions.Timeout,
                        socket.gaierror) as e:
                    
                    if retry_count < self.max_retries:
                        # Emit retry signal
                        self.retrying.emit(retry_count + 1, str(e))
                        
                        # Wait before retrying
                        for i in range(self.retry_delay):
                            if self._stop:
                                return
                            self.msleep(1000)
                        
                        # Continue to next retry
                        continue
                    else:
                        # Max retries exceeded
                        raise e
                        
                except Exception as e:
                    # Non-retryable error
                    raise e
                    
            # If we get here, all retries failed
            raise requests.exceptions.ConnectionError("Max retries exceeded")
            
        except Exception as e:
            self.failed.emit(str(e))

    def _load_state(self):
        """Load download state from JSON file"""
        try:
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE, "r") as f:
                    return json.load(f)
        except Exception:
            pass
        return None

    def _save_state(self, downloaded, file_path, url, version, total=0):
        """Save download state to JSON file"""
        try:
            state = {
                "url": url,
                "version": version,
                "file": file_path,
                "downloaded": downloaded,
                "total_size": total,
                "timestamp": time.time()
            }
            os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
            with open(STATE_FILE, "w") as f:
                json.dump(state, f)
        except Exception:
            pass

    def _cleanup_state(self):
        """Remove state file after successful download"""
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


class HomeTab(QWidget):
    def __init__(self, parent_app):
        super().__init__()
        self.parent_app = parent_app
        layout = QVBoxLayout(self)
        
        # Title and version
        self.label = QLabel(f"Hello 👋\nVersion {CURRENT_VERSION} v===v")
        self.label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.label)
        
        # Manual check button
        self.btn_check_now = QPushButton("🔍 Check for Updates Now")
        self.btn_check_now.clicked.connect(self.manual_check)
        layout.addWidget(self.btn_check_now)
        
        # Status label for manual checks
        self.check_status = QLabel("")
        self.check_status.setAlignment(Qt.AlignCenter)
        self.check_status.setStyleSheet("color: gray;")
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

    def manual_check(self):
        """Manual check for updates"""
        self.btn_check_now.setEnabled(False)
        self.check_status.setText("Checking for updates...")
        self.parent_app.check_for_updates(force=True)

    def show_update(self, version, download_callback):
        self.notice_label.setText(f"New version {version} available")
        self.btn_download.show()
        self.btn_dismiss.show()

        self.btn_download.clicked.connect(lambda: download_callback())
        self.btn_dismiss.clicked.connect(self.hide_update)

    def hide_update(self):
        self.notice_label.setText("")
        self.btn_download.hide()
        self.btn_dismiss.hide()
        self.btn_check_now.setEnabled(True)
        self.check_status.setText("")

    def update_check_status(self, message, is_success=True):
        """Update the status label for manual checks"""
        color = "green" if is_success else "red"
        self.check_status.setText(message)
        self.check_status.setStyleSheet(f"color: {color};")
        self.btn_check_now.setEnabled(True)
        
        # Clear message after 5 seconds
        if is_success:
            QTimer.singleShot(5000, lambda: self.check_status.setText(""))


class UpdateTab(QWidget):
    def __init__(self, parent_app):
        super().__init__()
        self.parent_app = parent_app
        layout = QVBoxLayout(self)

        self.status_label = QLabel("No updates in progress")
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)

        self.btn_pause = QPushButton("Pause")
        self.btn_resume = QPushButton("Resume")
        self.btn_download = QPushButton("Resume Download")
        self.btn_settings = QPushButton("⚙ Settings")

        self.btn_pause.setEnabled(False)
        self.btn_resume.setEnabled(False)
        self.btn_download.setEnabled(False)

        # Top button row
        top_btn_layout = QHBoxLayout()
        top_btn_layout.addWidget(self.btn_settings)
        top_btn_layout.addStretch()
        
        # Main button row
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.btn_download)
        btn_layout.addWidget(self.btn_pause)
        btn_layout.addWidget(self.btn_resume)

        layout.addLayout(top_btn_layout)
        layout.addWidget(self.status_label)
        layout.addWidget(self.progress_bar)
        layout.addLayout(btn_layout)

        self.thread = None
        self.latest_version = None
        self.download_url = None
        self.has_previous_download = False

        # Button events
        self.btn_pause.clicked.connect(self.pause)
        self.btn_resume.clicked.connect(self.resume)
        self.btn_download.clicked.connect(self.resume_download)
        self.btn_settings.clicked.connect(self.show_settings)

    def show_settings(self):
        """Show update settings dialog"""
        from PySide6.QtWidgets import QDialog, QFormLayout, QCheckBox, QSpinBox, QDialogButtonBox
        
        dialog = QDialog(self)
        dialog.setWindowTitle("Update Settings")
        layout = QFormLayout(dialog)
        
        config = Config.load()
        
        # Auto-check enabled
        cb_auto_check = QCheckBox()
        cb_auto_check.setChecked(config.get("auto_check_enabled", True))
        layout.addRow("Automatically check for updates:", cb_auto_check)
        
        # Check interval
        sb_interval = QSpinBox()
        sb_interval.setRange(1, 720)  # 1 hour to 30 days
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
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addRow(buttons)
        
        if dialog.exec() == QDialog.Accepted:
            # Save settings
            new_config = {
                "auto_check_enabled": cb_auto_check.isChecked(),
                "check_interval_hours": sb_interval.value(),
                "background_check": cb_background.isChecked(),
                "notify_on_available": cb_notify.isChecked()
            }
            Config.save(new_config)
            
            # Show confirmation
            QMessageBox.information(self, "Settings Saved", 
                                  "Update settings have been saved.")

    def check_for_resume(self):
        """Check if there's a download that can be resumed"""
        try:
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE, "r") as f:
                    state = json.load(f)
                
                # Check if the downloaded file still exists
                file_path = state.get("file", os.path.join(APP_DATA_DIR, f"innoselfupdate_v{CURRENT_VERSION}.exe"))
                if os.path.exists(file_path):
                    return state
                else:
                    # File was deleted - clean up invalid state
                    print("Download file missing, cleaning up invalid state")
                    if os.path.exists(STATE_FILE):
                        os.remove(STATE_FILE)
                    return None
        except Exception as e:
            print(f"Error reading state file: {e}")
            # Clean up corrupted state file
            if os.path.exists(STATE_FILE):
                os.remove(STATE_FILE)
        return None

    def update_progress_from_state(self, state):
        """Update progress bar from saved state"""
        if not state:
            return False
            
        downloaded = state.get("downloaded", 0)
        total_size = state.get("total_size", 0)
        
        if total_size > 0:
            progress_percent = int((downloaded / total_size) * 100)
            self.progress_bar.setValue(progress_percent)
            downloaded_mb = downloaded / (1024 * 1024)
            total_mb = total_size / (1024 * 1024) if total_size > 0 else 0
            
            if total_size > 0:
                self.status_label.setText(
                    f"Update {state.get('version', 'unknown')}: {progress_percent}% ({downloaded_mb:.1f}/{total_mb:.1f} MB)"
                )
            else:
                self.status_label.setText(
                    f"Update {state.get('version', 'unknown')}: {downloaded_mb:.1f} MB downloaded"
                )
            return True
        
        return False

    def validate_state(self):
        """Validate that the saved state is still valid"""
        state = self.check_for_resume()
        if not state:
            return False
        
        # Check if file exists and is not corrupted
        file_path = state.get("file", os.path.join(APP_DATA_DIR, f"innoselfupdate_v{CURRENT_VERSION}.exe"))
        if not os.path.exists(file_path):
            return False
        
        # Check if state is not too old (older than 24 hours)
        timestamp = state.get("timestamp", 0)
        if time.time() - timestamp > 86400:  # 24 hours
            print("State file is too old, cleaning up")
            if os.path.exists(STATE_FILE):
                os.remove(STATE_FILE)
            return False
        
        return True

    def set_update_info(self, url, version):
        self.latest_version = version
        self.download_url = url
        
        # Check if we can resume this specific update
        if self.validate_state():
            state = self.check_for_resume()
            if state and state.get("url") == url:
                self.has_previous_download = True
                self.update_progress_from_state(state)
                self.btn_download.setEnabled(True)
                self.btn_download.setText("Resume Download")
            else:
                self._cleanup_invalid_state()
                self.status_label.setText(f"Update {version} ready to download")
                self.btn_download.setEnabled(True)
                self.btn_download.setText("Download Update")
                self.progress_bar.setValue(0)
        else:
            self._cleanup_invalid_state()
            self.status_label.setText(f"Update {version} ready to download")
            self.btn_download.setEnabled(True)
            self.btn_download.setText("Download Update")
            self.progress_bar.setValue(0)

    def _cleanup_invalid_state(self):
        """Clean up invalid/corrupted state"""
        try:
            if os.path.exists(STATE_FILE):
                os.remove(STATE_FILE)
            
            # Also clean up partial download file if it exists
            temp_file = os.path.join(APP_DATA_DIR, f"innoselfupdate_v{CURRENT_VERSION}.exe")
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except:
                    pass
        except Exception:
            pass

    def resume_download(self):
        """Automatically resume download without asking user"""
        self.btn_download.setEnabled(False)
        
        # Validate state one more time before starting
        if not self.validate_state():
            # State is invalid, start fresh
            self._cleanup_invalid_state()
            self.status_label.setText(f"Starting fresh download of version {self.latest_version}...")
            self.progress_bar.setValue(0)
        
        self.start_download(self.download_url, self.latest_version)

    def start_download(self, url, version):
        self.status_label.setText(f"Downloading version {version}...")
        
        self.thread = UpdateThread(url, version)
        self.thread.progress.connect(self.progress_bar.setValue)
        self.thread.finished.connect(self.update_ready)
        self.thread.failed.connect(self.download_failed)
        self.thread.retrying.connect(self.on_retry)
        self.thread.start()
        
        self.btn_pause.setEnabled(True)
        self.btn_resume.setEnabled(False)

    def on_retry(self, retry_count, error_message):
        """Handle retry attempts"""
        self.status_label.setText(
            f"Connection error. Retrying... ({retry_count}/3) - {error_message[:50]}..."
        )

    def pause(self):
        if self.thread:
            self.thread.pause()
            self.status_label.setText(f"Download paused (v{self.latest_version})")
            self.btn_pause.setEnabled(False)
            self.btn_resume.setEnabled(True)

    def resume(self):
        if self.thread:
            self.thread.resume()
            self.status_label.setText(f"Downloading version {self.latest_version}...")
            self.btn_pause.setEnabled(True)
            self.btn_resume.setEnabled(False)

    def update_ready(self, file_path):
        self.status_label.setText(f"Download complete: {file_path}")
        self.progress_bar.setValue(100)
        self.btn_pause.setEnabled(False)
        self.btn_resume.setEnabled(False)
        
        # Verify file exists and has size
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            # Use the integrated installer with permission prompt
            parent = self.window() if self.window() else None
            if UpdateInstaller.install_update(file_path, APP_NAME, self.latest_version, parent):
                if parent:
                    QApplication.quit()
            else:
                # User declined or installation failed
                self.btn_download.setEnabled(True)
                self.btn_download.setText("Install Update")
                self.btn_download.clicked.disconnect()
                self.btn_download.clicked.connect(lambda: self.install_update_now(file_path))
        else:
            QMessageBox.warning(self, "Download Error", "Downloaded file is empty or missing")
            self.btn_download.setEnabled(True)

    def install_update_now(self, file_path):
        """Install update immediately without asking again"""
        if UpdateInstaller.install_update(file_path, APP_NAME, self.latest_version, ask_permission=False):
            self.window().close()  # Close the window

    def download_failed(self, error_msg):
        self.status_label.setText(f"Download failed: {error_msg}")
        self.btn_pause.setEnabled(False)
        self.btn_resume.setEnabled(False)
        self.btn_download.setEnabled(True)
        
        # Check if we need to clean up invalid state
        if not self.validate_state():
            self._cleanup_invalid_state()
        
        # Show error but don't force quit - user can retry
        QMessageBox.warning(self, "Download Failed", 
                           f"Error: {error_msg[:200]}\n\nYou can try again later.")


class InnoSelfUpdate(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Inno Self Update App")
        self.resize(500, 300)  # Slightly taller for new button

        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        self.home_tab = HomeTab(self)
        self.update_tab = UpdateTab(self)

        self.tabs.addTab(self.home_tab, "Home")
        self.tabs.addTab(self.update_tab, "Update")
        layout.addWidget(self.tabs)

        self.update_check_thread = None
        self.background_timer = QTimer()
        self.background_timer.timeout.connect(self.background_check)

        # Check for pending updates on startup
        QTimer.singleShot(100, self.on_startup)

    def on_startup(self):
        """Handle startup checks"""
        # First, check for pending updates
        pending_update = UpdateInstaller.check_pending_update()
        if pending_update:
            reply = QMessageBox.question(
                self,
                "Pending Update",
                f"An update to version {pending_update.get('new_version', 'unknown')} "
                "was downloaded but not installed.\n\n"
                "Would you like to install it now?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                # Install the pending update
                if UpdateInstaller.install_update(
                    pending_update["new_exe_path"],
                    APP_NAME,
                    pending_update["new_version"],
                    ask_permission=False
                ):
                    self.close()
                    return
            else:
                # User declined - clean up pending update
                try:
                    if os.path.exists(PENDING_UPDATE_FILE):
                        os.remove(PENDING_UPDATE_FILE)
                except:
                    pass
        
        # Then, check for any existing download and show its progress
        state = self.update_tab.check_for_resume()
        if state:
            # Show the progress immediately
            if self.update_tab.update_progress_from_state(state):
                # Switch to Update tab to show progress
                self.tabs.setCurrentIndex(1)
        else:
            # Clean up any invalid state
            self.update_tab._cleanup_invalid_state()
        
        # Perform initial update check
        self.check_for_updates(force=False)
        
        # Start background timer if enabled
        config = Config.load()
        if config.get("background_check", True):
            # Convert hours to milliseconds
            interval_hours = config.get("check_interval_hours", 24)
            interval_ms = interval_hours * 60 * 60 * 1000
            self.background_timer.start(interval_ms)

    def check_for_updates(self, force=False):
        """Check for updates (manual or automatic)"""
        config = Config.load()
        
        # Check if we should skip
        if not force and not Config.should_check_for_updates():
            if force:  # Manual check that was skipped
                self.home_tab.update_check_status("Skipped - checked recently", True)
            return
        
        # Start update check thread
        self.update_check_thread = UpdateCheckThread(force_check=force)
        self.update_check_thread.update_found.connect(self.on_update_found)
        self.update_check_thread.no_update.connect(self.on_no_update)
        self.update_check_thread.check_complete.connect(self.on_check_complete)
        self.update_check_thread.start()

    def background_check(self):
        """Background update check triggered by timer"""
        config = Config.load()
        if config.get("background_check", True):
            self.check_for_updates(force=False)

    def on_update_found(self, version, url):
        """Handle when an update is found"""
        config = Config.load()
        
        # Update UI
        self.home_tab.show_update(version, lambda: self.update_tab.start_download(url, version))
        self.update_tab.set_update_info(url, version)
        
        # Switch to update tab if background check found update
        if not QApplication.activeWindow():  # App might be minimized/not focused
            self.tabs.setCurrentIndex(1)
        
        # Show notification if enabled
        if config.get("notify_on_available", True):
            # Simple in-app notification
            self.home_tab.update_check_status(f"Update {version} available!", True)

    def on_no_update(self):
        """Handle when no update is found"""
        # Only show message for manual checks
        pass

    def on_check_complete(self, success, message):
        """Handle completion of update check"""
        # Update manual check status
        self.home_tab.update_check_status(message, success)
        
        # Update last check time if successful
        if success:
            Config.update_last_check_time()

    def closeEvent(self, event):
        """Handle app closure"""
        # Stop background timer
        self.background_timer.stop()
        
        # Stop update check thread if running
        if self.update_check_thread and self.update_check_thread.isRunning():
            self.update_check_thread.quit()
            self.update_check_thread.wait(1000)
        
        # Handle download in progress
        if hasattr(self.update_tab, 'thread') and self.update_tab.thread and self.update_tab.thread.isRunning():
            reply = QMessageBox.question(
                self, "Download in Progress",
                "A download is in progress. It will be saved and can be resumed later.\n"
                "Do you want to close the application?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                # Pause the download and save state
                if hasattr(self.update_tab, 'thread') and self.update_tab.thread:
                    self.update_tab.thread.pause()
                    # Give it a moment to save state
                    QTimer.singleShot(200, lambda: event.accept())
                else:
                    event.accept()
            else:
                event.ignore()
        else:
            event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    w = InnoSelfUpdate()
    w.show()
    sys.exit(app.exec())