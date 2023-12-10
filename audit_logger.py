import sqlite3
import datetime

class AuditLogger:
    def __init__(self, db_path='audit_log.db'):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self.create_audit_log_table()

    def create_audit_log_table(self):
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS audit_log
                              (id INTEGER PRIMARY KEY, timestamp TIMESTAMP, event_type TEXT, username TEXT, details TEXT)''')
        self.conn.commit()

    def log(self, event_type, username, details=""):
        timestamp = datetime.datetime.now()
        self.cursor.execute("INSERT INTO audit_log (timestamp, event_type, username, details) VALUES (?, ?, ?, ?)",
                            (timestamp, event_type, username, details))
        self.conn.commit()

    def close(self):
        self.conn.close()
