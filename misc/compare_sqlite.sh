#!/bin/bash

# SQLite Database Comparison Script
# Usage: ./compare_sqlite.sh <current_db> <new_db>

set -e

if [ $# -ne 2 ]; then
    echo "Usage: $0 <current_db> <new_db>"
    exit 1
fi

CURRENT_DB=$1
NEW_DB=$2

# Check if database files exist
if [ ! -f "$CURRENT_DB" ] || [ ! -f "$NEW_DB" ]; then
    echo "Error: One or both database files do not exist"
    exit 1
fi

echo "Comparing SQLite databases:"
echo "Current DB: $CURRENT_DB"
echo "New DB: $NEW_DB"
echo "----------------------------------------"

# Compare artifacts table
echo "Comparing artifacts table (group_id, artifact_id only)"

# Compare record counts
CURRENT_COUNT=$(sqlite3 "$CURRENT_DB" "SELECT COUNT(*) FROM artifacts;")
NEW_COUNT=$(sqlite3 "$NEW_DB" "SELECT COUNT(*) FROM artifacts;")
echo "Record count in Current DB: $CURRENT_COUNT"
echo "Record count in New DB: $NEW_COUNT"

if [ "$CURRENT_COUNT" != "$NEW_COUNT" ]; then
    echo "WARNING: Record counts for artifacts table are different!"
    echo "Difference: $(($NEW_COUNT - $CURRENT_COUNT)) records"
fi

# Create temporary directory for our files
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# Export group_id and artifact_id to temporary files for comparison
sqlite3 "$CURRENT_DB" "SELECT group_id, artifact_id FROM artifacts ORDER BY group_id, artifact_id;" > "$TEMP_DIR/current_artifacts.txt"
sqlite3 "$NEW_DB" "SELECT group_id, artifact_id FROM artifacts ORDER BY group_id, artifact_id;" > "$TEMP_DIR/new_artifacts.txt"

# Sort files in place to avoid pipeline issues
sort "$TEMP_DIR/current_artifacts.txt" -o "$TEMP_DIR/current_artifacts_sorted.txt"
sort "$TEMP_DIR/new_artifacts.txt" -o "$TEMP_DIR/new_artifacts_sorted.txt"

# Find records in Current DB but not in New DB
echo "Records in Current DB but not in New DB:"
DIFF_COUNT=$(comm -23 "$TEMP_DIR/current_artifacts_sorted.txt" "$TEMP_DIR/new_artifacts_sorted.txt" | tee "$TEMP_DIR/current_only.txt" | wc -l)
head -n 100 "$TEMP_DIR/current_only.txt"
if [ "$DIFF_COUNT" -gt 100 ]; then
    echo "... and $((DIFF_COUNT - 100)) more records"
fi

# Find records in New DB but not in Current DB
echo "Records in New DB but not in Current DB:"
DIFF_COUNT=$(comm -13 "$TEMP_DIR/current_artifacts_sorted.txt" "$TEMP_DIR/new_artifacts_sorted.txt" | tee "$TEMP_DIR/new_only.txt" | wc -l)
head -n 10 "$TEMP_DIR/new_only.txt"
if [ "$DIFF_COUNT" -gt 10 ]; then
    echo "... and $((DIFF_COUNT - 10)) more records"
fi

echo "----------------------------------------"
echo "Comparison completed." 