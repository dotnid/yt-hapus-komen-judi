import sys
import re
import unicodedata
import os
import pickle
import json
import time
import urllib.parse
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QFileDialog,
    QProgressBar, QMessageBox, QGroupBox, QSplitter, QCheckBox, QTabWidget, QTableWidget,
    QTableWidgetItem, QHeaderView
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, pyqtSlot, QSettings
from PyQt6.QtGui import QFont, QIcon

import google_auth_oauthlib.flow
import googleapiclient.discovery
import googleapiclient.errors
import googleapiclient.http
from google.auth.transport.requests import Request

# === API Configuration ===
SCOPES = ["https://www.googleapis.com/auth/youtube.force-ssl"]
CREDENTIALS_PICKLE_FILE = "token.pickle"
SETTINGS_FILE = "app_settings.json"
# Allow insecure HTTP for local testing (do not use in production)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

class CommentFilterWorker(QThread):
    progress_update = pyqtSignal(str)
    status_update = pyqtSignal(str)
    progress_value = pyqtSignal(int)
    finished_signal = pyqtSignal(int, int)  # total, deleted count
    oauth_required = pyqtSignal()
    
    def __init__(self, video_id, client_secrets_file, retry_on_error=True, retry_delay=5):
        super().__init__()
        self.video_id = video_id
        self.client_secrets_file = client_secrets_file
        self.youtube = None
        self.stopped = False
        self.retry_on_error = retry_on_error
        self.retry_delay = retry_delay
        self.max_retries = 3
    
    def stop(self):
        self.stopped = True
    
    def run(self):
        try:
            # Authenticate
            self.status_update.emit("Melakukan autentikasi...")
            self.youtube = self.get_authenticated_service()
            
            if self.stopped:
                return
                
            # Filter and delete comments
            self.filter_and_delete_comments()
        except Exception as e:
            self.status_update.emit(f"Error: {str(e)}")
    
    def get_authenticated_service(self):
        credentials = None
        # Load credentials from file if they exist
        if os.path.exists(CREDENTIALS_PICKLE_FILE):
            with open(CREDENTIALS_PICKLE_FILE, "rb") as token:
                credentials = pickle.load(token)
        
        # If there are no (valid) credentials available, run the OAuth flow
        if not credentials or not credentials.valid:
            if credentials and credentials.expired and credentials.refresh_token:
                # Refresh the credentials automatically
                credentials.refresh(Request())
            else:
                # Run the OAuth flow for the first time
                self.status_update.emit("Membutuhkan autentikasi OAuth. Silakan otentikasi di browser...")
                self.oauth_required.emit()
                flow = google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file(
                    self.client_secrets_file, SCOPES)
                credentials = flow.run_local_server(port=8080)
                
            # Save the credentials for the next run
            with open(CREDENTIALS_PICKLE_FILE, "wb") as token:
                pickle.dump(credentials, token)
        
        return googleapiclient.discovery.build("youtube", "v3", credentials=credentials)
    
    def normalize_text(self, text):
        """Return text in a more standardized ASCII form"""
        return unicodedata.normalize("NFKD", text)

    def contains_special_chars(self, text):
        """Check if there are special characters after normalization"""
        # normalized = self.normalize_text(text)
        # return bool(re.search(r"[^a-zA-Z0-9 ]", normalized))  # Only allow A-Z, a-z, 0-9, and spaces
        pattern = re.compile(r"[^a-zA-Z0-9\s!@#$%^&*()_+\-=\[\]{}|;:'\",.<>?/`~\\😊😂😍😎🤔👍👎❤️💔]")
        return bool(pattern.search(text))  # Jika ada karakter yang tidak diizinkan, return True

    
    def get_video_comments(self):
        """Get comments from video"""
        comments = []
        try:
            self.status_update.emit("Mengambil komentar...")
            request = self.youtube.commentThreads().list(
                part="snippet",
                videoId=self.video_id,
                textFormat="plainText",
                maxResults=100  # Limit number of comments to fetch
            )
            response = request.execute()
            
            for item in response.get("items", []):
                if self.stopped:
                    return comments
                    
                comment = item["snippet"]["topLevelComment"]["snippet"]
                comment_id = item["snippet"]["topLevelComment"]["id"]
                text = comment["textDisplay"]
                author = comment.get("authorDisplayName", "Unknown")
                published_at = comment.get("publishedAt", "Unknown")
                comments.append((comment_id, text, author, published_at))
            
            # Handle pagination if needed
            next_page_token = response.get("nextPageToken")
            while next_page_token and not self.stopped:
                self.status_update.emit(f"Mengambil komentar selanjutnya... (total: {len(comments)})")
                request = self.youtube.commentThreads().list(
                    part="snippet",
                    videoId=self.video_id,
                    textFormat="plainText",
                    maxResults=100,
                    pageToken=next_page_token
                )
                response = request.execute()
                
                for item in response.get("items", []):
                    if self.stopped:
                        return comments
                        
                    comment = item["snippet"]["topLevelComment"]["snippet"]
                    comment_id = item["snippet"]["topLevelComment"]["id"]
                    text = comment["textDisplay"]
                    author = comment.get("authorDisplayName", "Unknown")
                    published_at = comment.get("publishedAt", "Unknown")
                    comments.append((comment_id, text, author, published_at))
                
                next_page_token = response.get("nextPageToken")
            
        except googleapiclient.errors.HttpError as e:
            self.status_update.emit(f"Error API YouTube: {str(e)}")
            self.progress_update.emit(f"Detail error: {str(e)}")
        except Exception as e:
            self.status_update.emit(f"Error mengambil komentar: {str(e)}")
        
        return comments
    
    def delete_comment(self, comment_id, retries=0):
        """Delete comment by ID with retry logic"""
        if self.stopped:
            return False
            
        try:
            self.youtube.comments().delete(id=comment_id).execute()
            return True
        except googleapiclient.errors.HttpError as e:
            error_msg = str(e)
            
            # Check for specific error types
            if "processingFailure" in error_msg:
                self.progress_update.emit(f"⚠️ Gagal menghapus komentar (processing failure): {comment_id}")
                self.progress_update.emit(f"   API YouTube tidak dapat memproses permintaan ini.")
                
                # Try using commentThreads().delete() instead if this is the first attempt
                if retries == 0:
                    try:
                        self.progress_update.emit(f"🔄 Mencoba metode alternatif untuk menghapus komentar...")
                        # Get thread ID from the video and comment ID
                        thread_request = self.youtube.commentThreads().list(
                            part="id",
                            videoId=self.video_id,
                            textFormat="plainText",
                            maxResults=100
                        )
                        thread_response = thread_request.execute()
                        
                        for item in thread_response.get("items", []):
                            item_comment_id = item["snippet"]["topLevelComment"]["id"]
                            if item_comment_id == comment_id:
                                thread_id = item["id"]
                                self.youtube.commentThreads().delete(id=thread_id).execute()
                                self.progress_update.emit(f"✅ Berhasil menghapus komentar dengan metode alternatif.")
                                return True
                    except Exception as thread_e:
                        self.progress_update.emit(f"❌ Metode alternatif juga gagal: {str(thread_e)}")
                
                # If retry is enabled and we haven't exceeded max retries
                if self.retry_on_error and retries < self.max_retries:
                    retries += 1
                    self.progress_update.emit(f"🔄 Mencoba lagi ({retries}/{self.max_retries}) dalam {self.retry_delay} detik...")
                    time.sleep(self.retry_delay)
                    return self.delete_comment(comment_id, retries)
                    
                return False
                
            elif "404" in error_msg:
                self.progress_update.emit(f"⚠️ Komentar tidak ditemukan (mungkin sudah dihapus): {comment_id}")
                return False
                
            else:
                self.progress_update.emit(f"⚠️ Error API YouTube: {error_msg}")
                
                # If retry is enabled and we haven't exceeded max retries
                if self.retry_on_error and retries < self.max_retries:
                    retries += 1
                    self.progress_update.emit(f"🔄 Mencoba lagi ({retries}/{self.max_retries}) dalam {self.retry_delay} detik...")
                    time.sleep(self.retry_delay)
                    return self.delete_comment(comment_id, retries)
                    
                return False
                
        except Exception as e:
            self.progress_update.emit(f"⚠️ Error menghapus komentar {comment_id}: {str(e)}")
            
            # If retry is enabled and we haven't exceeded max retries
            if self.retry_on_error and retries < self.max_retries:
                retries += 1
                self.progress_update.emit(f"🔄 Mencoba lagi ({retries}/{self.max_retries}) dalam {self.retry_delay} detik...")
                time.sleep(self.retry_delay)
                return self.delete_comment(comment_id, retries)
                
            return False
    
    def hide_comment(self, comment_id, retries=0):
        """Hide comment by ID with retry logic"""
        if self.stopped:
            return False

        try:
            self.youtube.comments().setModerationStatus(
                id=comment_id,
                moderationStatus="rejected",
                banAuthor=True
            ).execute()
            
            self.progress_update.emit(f"✅ Komentar {comment_id} berhasil disembunyikan.")
            return True

        except googleapiclient.errors.HttpError as e:
            error_msg = str(e)
            
            # Jika API gagal memproses permintaan
            if "processingFailure" in error_msg:
                self.progress_update.emit(f"⚠️ Gagal menyembunyikan komentar (processing failure): {comment_id}")
                self.progress_update.emit(f"   API YouTube tidak dapat memproses permintaan ini.")

            # Jika komentar tidak ditemukan
            elif "404" in error_msg:
                self.progress_update.emit(f"⚠️ Komentar tidak ditemukan (mungkin sudah dihapus): {comment_id}")
                return False

            # Jika terjadi error lain, coba ulangi hingga batas maksimal
            else:
                self.progress_update.emit(f"⚠️ Error API YouTube: {error_msg}")

            if self.retry_on_error and retries < self.max_retries:
                retries += 1
                self.progress_update.emit(f"🔄 Mencoba lagi ({retries}/{self.max_retries}) dalam {self.retry_delay} detik...")
                time.sleep(self.retry_delay)
                return self.hide_comment(comment_id, retries)

            return False

        except Exception as e:
            self.progress_update.emit(f"⚠️ Error menyembunyikan komentar {comment_id}: {str(e)}")

            if self.retry_on_error and retries < self.max_retries:
                retries += 1
                self.progress_update.emit(f"🔄 Mencoba lagi ({retries}/{self.max_retries}) dalam {self.retry_delay} detik...")
                time.sleep(self.retry_delay)
                return self.hide_comment(comment_id, retries)

            return False
        
    def filter_and_delete_comments(self):
        """Filter comments and delete if they contain special characters"""
        comments = self.get_video_comments()
        
        if not comments:
            self.status_update.emit("Tidak ada komentar yang ditemukan atau terjadi error.")
            self.finished_signal.emit(0, 0)
            return
        
        self.status_update.emit(f"Ditemukan {len(comments)} komentar untuk diproses.")
        deleted_count = 0
        skipped_count = 0
        
        for i, (comment_id, text, author, published_at) in enumerate(comments):
            if self.stopped:
                self.finished_signal.emit(len(comments), deleted_count)
                return
                
            # Update progress bar
            progress_percent = int((i + 1) / len(comments) * 100)
            self.progress_value.emit(progress_percent)
            
            # Format date for display
            date_str = published_at[:10] if published_at and published_at != "Unknown" else "Unknown"
            
            # Show full comment text in the log
            self.progress_update.emit(f"Komentar #{i+1}/{len(comments)} oleh {author} ({date_str}):")
            self.progress_update.emit(f"ID: {comment_id}")
            self.progress_update.emit(f"Text: {text}")
            
            if self.contains_special_chars(text):
                self.progress_update.emit(f"🚨 Komentar mengandung karakter khusus. Mencoba menghapus...")
                if self.hide_comment(comment_id):
                    deleted_count += 1
                    self.progress_update.emit(f"✅ Komentar berhasil dihapus!")
                else:
                    skipped_count += 1
                    self.progress_update.emit(f"❌ Gagal menghapus komentar.")
            else:
                self.progress_update.emit(f"✅ Komentar tidak mengandung karakter khusus. Dibiarkan.")
            
            # Add separator for readability
            self.progress_update.emit("-------------------------------------------")
        
        self.status_update.emit(f"Selesai: {deleted_count} komentar dihapus, {skipped_count} gagal dihapus, dari total {len(comments)} komentar.")
        self.finished_signal.emit(len(comments), deleted_count)
  
class YouTubeAPI:
    def __init__(self, client_secrets_file):
        self.client_secrets_file = client_secrets_file
        self.youtube = None
        self.stopped = False
        self.channel_id = None
        self.run()

    def run(self):
        try:
            # Authenticate
            self.youtube = self.authenticate()
            
            if self.stopped:
                return

        except Exception as e:
            print(f"Error: {str(e)}")

    def authenticate(self):
        credentials = None
        # Load credentials from file if they exist
        if os.path.exists(CREDENTIALS_PICKLE_FILE):
            with open(CREDENTIALS_PICKLE_FILE, "rb") as token:
                credentials = pickle.load(token)
        
        # If there are no (valid) credentials available, run the OAuth flow
        if not credentials or not credentials.valid:
            if credentials and credentials.expired and credentials.refresh_token:
                # Refresh the credentials automatically
                credentials.refresh(Request())
            else:
                # Run the OAuth flow for the first time
                # self.status_update.emit("Membutuhkan autentikasi OAuth. Silakan otentikasi di browser...")
                # self.oauth_required.emit()
                flow = google_auth_oauthlib.flow.InstalledAppFlow.from_client_secrets_file(
                    self.client_secrets_file, SCOPES)
                credentials = flow.run_local_server(port=8080)
                
            # Save the credentials for the next run
            with open(CREDENTIALS_PICKLE_FILE, "wb") as token:
                pickle.dump(credentials, token)
        
        return googleapiclient.discovery.build("youtube", "v3", credentials=credentials)
    
    def get_channel_id(self):
        response = self.youtube.channels().list(
            part="id",
            mine=True  # Ambil ID channel milik akun yang diautentikasi
        ).execute()
        return response["items"][0]["id"]

    def get_banned_users(self):
        try:
            if not self.channel_id:
                self.channel_id = self.get_channel_id()

            response = self.youtube.commentThreads().list(
                part="snippet",
                moderationStatus="heldForReview",
                allThreadsRelatedToChannelId=self.channel_id,
                maxResults=50
            ).execute()
            
            banned_users = []
            for item in response.get("items", []):
                author = item["snippet"]["topLevelComment"]["snippet"].get("authorDisplayName", "Unknown")
                message = item["snippet"]["topLevelComment"]["snippet"].get("textDisplay", "Unknown")
                channel_id = item["snippet"]["topLevelComment"]["snippet"].get("authorChannelId", {}).get("value", "Unknown")
                banned_users.append((author, message, channel_id))
            print("Banned users:", banned_users)
            return banned_users
        except Exception as e:
            print(f'Error get banned users: {e}')
            return []
    
    def unban_user(self, channel_id):
        try:
            self.youtube.comments().setModerationStatus(
                id=channel_id,
                moderationStatus="published"
            ).execute()
            return True
        except Exception as e:
            return False
        
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.youtube_api = None
        self.init_ui()
        self.worker = None
        self.load_settings()
    
    def init_ui(self):
        self.setWindowTitle("YouTube Comment Manager")
        self.setGeometry(100, 100, 1000, 700)
        
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        self.tabs = QTabWidget()
        
        self.comment_filter_tab = QWidget()
        self.banned_users_tab = QWidget()
        
        self.tabs.addTab(self.comment_filter_tab, "Filter Komentar")
        # self.tabs.addTab(self.banned_users_tab, "Pengguna Diblokir")
        
        main_layout.addWidget(self.tabs)
        
        self.setup_comment_filter_ui()
        # self.setup_banned_users_ui()

    def setup_comment_filter_ui(self):
        layout = QVBoxLayout(self.comment_filter_tab)
        # Title
        title_label = QLabel("YouTube Comment Manager")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)
        
        # Configuration section
        config_group = QGroupBox("Konfigurasi")
        config_layout = QVBoxLayout()
        
        # Client Secrets file selection
        secrets_layout = QHBoxLayout()
        secrets_label = QLabel("Client Secrets File:")
        self.secrets_path = QLineEdit()
        self.secrets_path.setPlaceholderText("Pilih file client_secret_*.json")
        secrets_button = QPushButton("Browse...")
        secrets_button.clicked.connect(self.browse_secrets_file)
        
        secrets_layout.addWidget(secrets_label)
        secrets_layout.addWidget(self.secrets_path)
        secrets_layout.addWidget(secrets_button)
        config_layout.addLayout(secrets_layout)
        
        # Video ID input
        video_layout = QHBoxLayout()
        video_label = QLabel("Video ID/URL:")
        self.video_id_input = QLineEdit()
        self.video_id_input.setPlaceholderText("Masukkan ID video atau URL YouTube")
        
        video_layout.addWidget(video_label)
        video_layout.addWidget(self.video_id_input)
        config_layout.addLayout(video_layout)
        
        # Retry options
        retry_layout = QHBoxLayout()
        self.retry_checkbox = QCheckBox("Coba lagi jika gagal")
        self.retry_checkbox.setChecked(True)
        retry_layout.addWidget(self.retry_checkbox)
        config_layout.addLayout(retry_layout)
        
        # Remember settings
        remember_layout = QHBoxLayout()
        self.remember_checkbox = QCheckBox("Simpan lokasi file client secrets")
        self.remember_checkbox.setChecked(True)
        remember_layout.addWidget(self.remember_checkbox)
        config_layout.addLayout(remember_layout)
        
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)
        
        # Action buttons
        buttons_layout = QHBoxLayout()
        self.start_button = QPushButton("Mulai Filter")
        self.start_button.clicked.connect(self.start_filtering)
        self.stop_button = QPushButton("Berhenti")
        self.stop_button.clicked.connect(self.stop_filtering)
        self.stop_button.setEnabled(False)
        self.clear_button = QPushButton("Bersihkan Log")
        self.clear_button.clicked.connect(self.clear_logs)
        
        buttons_layout.addWidget(self.start_button)
        buttons_layout.addWidget(self.stop_button)
        buttons_layout.addWidget(self.clear_button)
        layout.addLayout(buttons_layout)
        
        # Progress section
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout()
        
        # Progress bar
        self.progress_bar = QProgressBar()
        progress_layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("Siap")
        progress_layout.addWidget(self.status_label)
        
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
        # Logs area
        logs_group = QGroupBox("Detail Proses")
        logs_layout = QVBoxLayout()
        
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        logs_layout.addWidget(self.log_output)
        
        logs_group.setLayout(logs_layout)
        layout.addWidget(logs_group, stretch=1)
        
        # Set up the splitter for resizable sections
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(config_group)
        splitter.addWidget(progress_group)
        splitter.addWidget(logs_group)
        layout.addWidget(splitter)
    
    def setup_banned_users_ui(self):
        layout = QVBoxLayout(self.banned_users_tab)
        
        self.banned_users_table = QTableWidget()
        self.banned_users_table.setColumnCount(3)
        self.banned_users_table.setHorizontalHeaderLabels(["Nama Pengguna", "Pesan", "Aksi"])
        self.banned_users_table.horizontalHeader().setStretchLastSection(True)
        self.banned_users_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.banned_users_table)

        self.load_banned_users_button = QPushButton("Muat Daftar Banned Users")
        self.load_banned_users_button.clicked.connect(self.load_banned_users)
        layout.addWidget(self.load_banned_users_button)

    def load_settings(self):
        """Load saved settings"""
        try:
            if os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE, 'r') as f:
                    settings = json.load(f)
                    
                # Load client secrets path
                if "client_secrets_path" in settings:
                    path = settings["client_secrets_path"]
                    if os.path.exists(path):
                        self.secrets_path.setText(path)
                        self.log_output.append(f"[INFO] Loaded saved client secrets path: {path}")
                    else:
                        self.log_output.append(f"[WARNING] Saved client secrets path not found: {path}")
                
                # Load other settings
                if "remember_path" in settings:
                    self.remember_checkbox.setChecked(settings["remember_path"])
                
                if "retry_on_error" in settings:
                    self.retry_checkbox.setChecked(settings["retry_on_error"])
                    
        except Exception as e:
            self.log_output.append(f"[ERROR] Failed to load settings: {str(e)}")
    
    def save_settings(self):
        """Save settings to file"""
        try:
            settings = {
                "remember_path": self.remember_checkbox.isChecked(),
                "retry_on_error": self.retry_checkbox.isChecked()
            }
            
            # Save client secrets path if remember is checked
            if self.remember_checkbox.isChecked():
                path = self.secrets_path.text().strip()
                if path and os.path.exists(path):
                    settings["client_secrets_path"] = path
            
            with open(SETTINGS_FILE, 'w') as f:
                json.dump(settings, f)
                
            self.log_output.append("[INFO] Settings saved")
                
        except Exception as e:
            self.log_output.append(f"[ERROR] Failed to save settings: {str(e)}")
    
    def browse_secrets_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Client Secrets File", "", 
            "JSON Files (*.json)"
        )
        if file_path:
            self.secrets_path.setText(file_path)
            if self.remember_checkbox.isChecked():
                self.save_settings()
    
    def extract_video_id(self, input_text):
        """Extract video ID from a YouTube URL or return the input if it's already an ID"""
        # Common YouTube URL patterns
        patterns = [
            r'(?:https?:\/\/)?(?:www\.)?youtube\.com\/watch\?v=([^&\s]+)',
            r'(?:https?:\/\/)?(?:www\.)?youtu\.be\/([^\?\s]+)',
            r'(?:https?:\/\/)?(?:www\.)?youtube\.com\/embed\/([^\?\s]+)',
            r'(?:https?:\/\/)?(?:www\.)?youtube\.com\/v\/([^\?\s]+)',
            r'(?:https?:\/\/)?(?:www\.)?youtube\.com\/shorts\/([^\?\s]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, input_text)
            if match:
                return match.group(1)
        
        # If no pattern matches, assume it's already a video ID
        return input_text
    
    def start_filtering(self):
        input_text = self.video_id_input.text().strip()
        client_secrets = self.secrets_path.text().strip()
        
        if not input_text:
            QMessageBox.warning(self, "Input Error", "Silakan masukkan ID video atau URL YouTube!")
            return
        
        # Extract video ID from URL if needed
        video_id = self.extract_video_id(input_text)
        
        if not client_secrets or not os.path.exists(client_secrets):
            QMessageBox.warning(self, "Input Error", "Silakan pilih file client secrets yang valid!")
            return
        
        # Save settings if remember is checked
        if self.remember_checkbox.isChecked():
            self.save_settings()
        
        # Clear previous logs
        self.log_output.clear()
        self.progress_bar.setValue(0)
        
        # Log the extracted video ID
        self.log_output.append(f"[INFO] Video ID yang diproses: {video_id}")
        if video_id != input_text:
            self.log_output.append(f"[INFO] ID diekstrak dari URL: {input_text}")
        
        # Disable/enable buttons
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        # Create and start worker thread
        self.worker = CommentFilterWorker(
            video_id, 
            client_secrets,
            retry_on_error=self.retry_checkbox.isChecked()
        )
        self.worker.progress_update.connect(self.update_log)
        self.worker.status_update.connect(self.update_status)
        self.worker.progress_value.connect(self.progress_bar.setValue)
        self.worker.finished_signal.connect(self.process_finished)
        self.worker.oauth_required.connect(self.show_oauth_message)
        self.worker.start()
    
    def stop_filtering(self):
        if self.worker:
            self.worker.stop()
            self.status_label.setText("Menghentikan proses...")
    
    def clear_logs(self):
        self.log_output.clear()
        self.log_output.append("[INFO] Log dibersihkan")
    
    def load_banned_users(self):
        if not self.youtube_api:
            # QMessageBox.warning(self, "Error", "Silakan autentikasi terlebih dahulu!")
            client_secrets_file = self.secrets_path.text().strip()
            if not client_secrets_file or not os.path.exists(client_secrets_file):
                QMessageBox.warning(self, "Input Error", "Silakan pilih file client secrets yang valid!")
                return
            self.youtube_api = YouTubeAPI(client_secrets_file)
            if not self.youtube_api:
                return
        
        banned_users = self.youtube_api.get_banned_users()
        self.banned_users_table.setRowCount(len(banned_users))
        
        for row, (author, message, channel_id) in enumerate(banned_users):
            self.banned_users_table.setItem(row, 0, QTableWidgetItem(author))
            self.banned_users_table.setItem(row, 1, QTableWidgetItem(message))
            # **Mengatur Lebar Kolom Agar 100%**
            self.banned_users_table.horizontalHeader().setStretchLastSection(True)
            self.banned_users_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
            unban_button = QPushButton("Unban")
            unban_button.clicked.connect(lambda _, cid=channel_id: self.unban_user(cid))
            self.banned_users_table.setCellWidget(row, 2, unban_button)
    
    def unban_user(self, channel_id):
        if self.youtube_api.unban_user(channel_id):
            QMessageBox.information(self, "Sukses", "Pengguna berhasil di-unban!")
            self.load_banned_users()
        else:
            QMessageBox.warning(self, "Gagal", "Gagal melakukan unban pengguna.")

    @pyqtSlot(str)
    def update_log(self, message):
        self.log_output.append(message)
        # Scroll to the bottom
        scroll_bar = self.log_output.verticalScrollBar()
        scroll_bar.setValue(scroll_bar.maximum())
    
    @pyqtSlot(str)
    def update_status(self, message):
        self.status_label.setText(message)
        # Also add to log
        self.log_output.append(f"[STATUS] {message}")
    
    @pyqtSlot(int, int)
    def process_finished(self, total, deleted):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setValue(100)
        
        # Show summary
        QMessageBox.information(
            self, 
            "Proses Selesai",
            f"Proses filter komentar selesai!\n\n"
            f"Total komentar diproses: {total}\n"
            f"Jumlah komentar dihapus: {deleted}"
        )
    
    @pyqtSlot()
    def show_oauth_message(self):
        QMessageBox.information(
            self,
            "OAuth Authentication",
            "Browser akan terbuka untuk autentikasi.\n\n"
            "Silakan login dengan akun Google Anda dan berikan izin yang diminta."
        )
    
    def closeEvent(self, event):
        """Save settings when app is closed"""
        if self.remember_checkbox.isChecked():
            self.save_settings()
        event.accept()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = MainWindow()
    window.show()
    sys.exit(app.exec())