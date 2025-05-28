#!/bin/bash
# Palicoin Backup Script

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="$HOME/palicoin-backups/backup_$TIMESTAMP"

echo "💾 Creating Palicoin backup..."

mkdir -p "$BACKUP_DIR"
cp -r ~/.palicoin "$BACKUP_DIR/"
cp -r ~/.bitcoin "$BACKUP_DIR/"

tar -czf "$HOME/palicoin-backup-$TIMESTAMP.tar.gz" -C "$BACKUP_DIR" .

echo "✅ Backup created: palicoin-backup-$TIMESTAMP.tar.gz"
