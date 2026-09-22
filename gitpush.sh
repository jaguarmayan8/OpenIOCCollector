#!/bin/bash

cd /home/chap/OpenIOCCollector || exit 1

LOG_FILE="/home/chap/OpenIOCCollector/cron.log"
echo "===== $(date) =====" >> "$LOG_FILE"

# Make sure we have a proper PATH
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Run the collector
echo "$(date) - Starting collector..." >> "$LOG_FILE"
/usr/bin/docker compose up --build -d >> "$LOG_FILE" 2>&1
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo "$(date) - ERROR: Collector failed with exit code $EXIT_CODE" >> "$LOG_FILE"
else
    echo "$(date) - Collector finished successfully" >> "$LOG_FILE"
fi

# Push to GitHub
echo "$(date) - Checking for new files..." >> "$LOG_FILE"
git add Output/ >> "$LOG_FILE" 2>&1

if git diff --cached --quiet; then
    echo "$(date) - No new files to push" >> "$LOG_FILE"
else
    git commit -m "Daily IOC update - $(date +'%Y-%m-%d %H:%M')" >> "$LOG_FILE" 2>&1
    git push origin main >> "$LOG_FILE" 2>&1
    echo "$(date) - Successfully pushed to GitHub" >> "$LOG_FILE"
fi

echo "$(date) - Job finished" >> "$LOG_FILE"
echo "" >> "$LOG_FILE"
