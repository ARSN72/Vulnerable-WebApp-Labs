import sqlite3

DB_NAME = "database.db"

def get_db_connection():
    """Establish a connection to the database."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# Now run the migration script
with get_db_connection() as conn:
    conn.execute("ALTER TABLE posts ADD COLUMN timestamp TEXT")
    print("✅ Timestamp column added successfully.")

# Update existing posts with a default timestamp
from datetime import datetime

with get_db_connection() as conn:
    default_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("UPDATE posts SET timestamp = ? WHERE timestamp IS NULL", (default_time,))
    print("✅ Default timestamps updated for existing posts.")
