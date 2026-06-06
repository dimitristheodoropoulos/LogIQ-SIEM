#!/bin/bash

# LogIQ MongoDB Backup Script

# --- Configuration ---
# You can adjust these variables or source them from a separate config file
MONGO_URI="mongodb://localhost:27017" # MongoDB connection URI
DB_NAME="logiq"                      # Database name to backup
BACKUP_BASE_DIR="./backups"          # Base directory where backups will be stored
RETENTION_DAYS=7                     # Number of days to keep old backups (e.g., 7 days)

# --- Check for mongodump ---
if ! command -v mongodump &> /dev/null
then
    echo "Error: mongodump command not found."
    echo "Please ensure MongoDB client tools are installed and available in your PATH."
    echo "On Debian/Ubuntu, you might need to install 'mongodb-org-tools' or 'mongodb-clients'."
    exit 1
fi

# --- Create Backup Directory ---
# Ensures the base backup directory exists
mkdir -p "$BACKUP_BASE_DIR"

if [ ! -d "$BACKUP_BASE_DIR" ]; then
    echo "Error: Could not create or access backup directory: $BACKUP_BASE_DIR"
    echo "Please check permissions or path."
    exit 1
fi

# --- Generate Timestamp for Unique Backup Folder ---
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_TARGET_PATH="${BACKUP_BASE_DIR}/${DB_NAME}_backup_${TIMESTAMP}"

echo "----------------------------------------------------"
echo "Starting MongoDB backup for database: '$DB_NAME'"
echo "Backup path: '$BACKUP_TARGET_PATH'"
echo "Timestamp: $TIMESTAMP"
echo "----------------------------------------------------"

# --- Execute mongodump ---
# The --gzip option compresses the backup files, saving space.
# The --archive option outputs the backup to a single archive file, making it easier to manage.
# (If you prefer separate files for each collection, remove --archive and --gzip, and keep --out="$BACKUP_TARGET_PATH")
mongodump --uri="$MONGO_URI" --db="$DB_NAME" --archive --gzip > "$BACKUP_TARGET_PATH.gz"

# --- Check Backup Status ---
if [ $? -eq 0 ]; then
    echo "Backup completed successfully to '$BACKUP_TARGET_PATH.gz'."
    echo "File size: $(du -h "$BACKUP_TARGET_PATH.gz" | awk '{print $1}')"
else
    echo "Error: MongoDB backup failed!"
    echo "Please check mongodump output for details (e.g., connection issues, permissions)."
    exit 1
fi

# --- Clean Old Backups (Retention Policy) ---
echo "----------------------------------------------------"
echo "Applying retention policy: Deleting backups older than $RETENTION_DAYS days..."

# Find and delete files older than RETENTION_DAYS in the base backup directory
# -mtime +N: Files modified more than N*24 hours ago
find "$BACKUP_BASE_DIR" -maxdepth 1 -type f -name "${DB_NAME}_backup_*.gz" -mtime +"$RETENTION_DAYS" -delete -print

# Also delete empty directories that might be left from previous non-gzipped backups
find "$BACKUP_BASE_DIR" -maxdepth 1 -type d -name "${DB_NAME}_backup_*" -empty -delete

echo "Old backups cleaned. (Files deleted are listed above, if any.)"
echo "----------------------------------------------------"

exit 0 # Script finished successfully