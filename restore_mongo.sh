#!/bin/bash

# Ρυθμίσεις - άλλαξε ανάλογα με το περιβάλλον σου
MONGO_URI="mongodb://localhost:27017"
DB_NAME="logiq"
BACKUP_DIR="./backups"

# Χρήση πρώτου ορίσματος ως φάκελος backup, αν δεν δοθεί παίρνουμε το τελευταίο backup
BACKUP_PATH=$1

if [ -z "$BACKUP_PATH" ]; then
    # Βρίσκει το πιο πρόσφατο backup φάκελο
    BACKUP_PATH=$(ls -td ${BACKUP_DIR}/${DB_NAME}_backup_* | head -1)
fi

if [ ! -d "$BACKUP_PATH" ]; then
    echo "Ο φάκελος backup δεν βρέθηκε: $BACKUP_PATH"
    exit 1
fi

echo "Ξεκινάει η επαναφορά της βάσης $DB_NAME από το backup $BACKUP_PATH"

# Εκτέλεση επαναφοράς με mongorestore (πρέπει να είναι εγκατεστημένο)
mongorestore --uri="$MONGO_URI" --db="$DB_NAME" --drop "$BACKUP_PATH/$DB_NAME"

if [ $? -eq 0 ]; then
    echo "Επαναφορά ολοκληρώθηκε επιτυχώς."
else
    echo "Σφάλμα κατά την επαναφορά."
fi
