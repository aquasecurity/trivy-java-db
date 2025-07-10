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

# Create temporary directory for our files
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

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

# Export group_id and artifact_id to temporary files for comparison
sqlite3 "$CURRENT_DB" "SELECT group_id, artifact_id FROM artifacts;" > "$TEMP_DIR/current_artifacts.txt"
sqlite3 "$NEW_DB" "SELECT group_id, artifact_id FROM artifacts;" > "$TEMP_DIR/new_artifacts.txt"

# Sort files in place for comm command
LC_ALL=C sort -b "$TEMP_DIR/current_artifacts.txt" -o "$TEMP_DIR/current_artifacts_sorted.txt"
LC_ALL=C sort -b "$TEMP_DIR/new_artifacts.txt" -o "$TEMP_DIR/new_artifacts_sorted.txt"

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

# Compare indices table based on SHA1 hash
echo "Comparing indices table (SHA1-based comparison, ignoring common GAVs)"

# Compare record counts
CURRENT_COUNT=$(sqlite3 "$CURRENT_DB" "SELECT COUNT(*) FROM indices;")
NEW_COUNT=$(sqlite3 "$NEW_DB" "SELECT COUNT(*) FROM indices;")
echo "Record count in Current DB: $CURRENT_COUNT"
echo "Record count in New DB: $NEW_COUNT"

if [ "$CURRENT_COUNT" != "$NEW_COUNT" ]; then
    echo "WARNING: Record counts for indices table are different!"
    echo "Difference: $(($NEW_COUNT - $CURRENT_COUNT)) records"
fi

# Extract unique SHA1 values from both databases
sqlite3 "$CURRENT_DB" "SELECT DISTINCT hex(i.sha1) FROM indices i;" > "$TEMP_DIR/current_sha1.txt"
sqlite3 "$NEW_DB" "SELECT DISTINCT hex(i.sha1) FROM indices i;" > "$TEMP_DIR/new_sha1.txt"

# Sort SHA1 values
LC_ALL=C sort -u "$TEMP_DIR/current_sha1.txt" -o "$TEMP_DIR/current_sha1_sorted.txt"
LC_ALL=C sort -u "$TEMP_DIR/new_sha1.txt" -o "$TEMP_DIR/new_sha1_sorted.txt"

# Export all GAVs from both databases for checking common GAVs
sqlite3 "$CURRENT_DB" "SELECT a.group_id || '|' || a.artifact_id || '|' || 
CASE WHEN instr(i.version, '-') > 0 THEN substr(i.version, 1, instr(i.version, '-') - 1) ELSE i.version END 
FROM indices i JOIN artifacts a ON i.artifact_id = a.id;" > "$TEMP_DIR/current_gavs.txt"

sqlite3 "$NEW_DB" "SELECT a.group_id || '|' || a.artifact_id || '|' || 
CASE WHEN instr(i.version, '-') > 0 THEN substr(i.version, 1, instr(i.version, '-') - 1) ELSE i.version END 
FROM indices i JOIN artifacts a ON i.artifact_id = a.id;" > "$TEMP_DIR/new_gavs.txt"

# Sort GAV lists for faster lookup
LC_ALL=C sort -u "$TEMP_DIR/current_gavs.txt" -o "$TEMP_DIR/current_gavs_sorted.txt"
LC_ALL=C sort -u "$TEMP_DIR/new_gavs.txt" -o "$TEMP_DIR/new_gavs_sorted.txt"

# Find SHA1 values in Current DB but not in New DB
echo "SHA1 values in Current DB but not in New DB (excluding GAVs present in both DBs):"
DIFF_COUNT=0
DISPLAY_COUNT=0

comm -23 "$TEMP_DIR/current_sha1_sorted.txt" "$TEMP_DIR/new_sha1_sorted.txt" | while read sha1; do
    # Get GAVs for this SHA1 from Current DB
    sqlite3 "$CURRENT_DB" "SELECT a.group_id || '|' || a.artifact_id || '|' || 
    CASE WHEN instr(i.version, '-') > 0 
         THEN substr(i.version, 1, instr(i.version, '-') - 1) 
         ELSE i.version END AS gav
    FROM indices i JOIN artifacts a ON i.artifact_id = a.id 
    WHERE hex(i.sha1) = '$sha1';" > "$TEMP_DIR/current_sha1_gavs.txt"
    
    # Check if any of these GAVs exist in New DB
    GAV_IN_BOTH=false
    while read gav; do
        if grep -q "^$gav$" "$TEMP_DIR/new_gavs_sorted.txt"; then
            GAV_IN_BOTH=true
            break
        fi
    done < "$TEMP_DIR/current_sha1_gavs.txt"
    
    # Skip this SHA1 if any of its GAVs exist in both DBs
    if [ "$GAV_IN_BOTH" = true ]; then
        continue
    fi
    
    # Otherwise, display this SHA1 and its GAVs
    DIFF_COUNT=$((DIFF_COUNT + 1))
    
    # Only show the first 10 items
    if [ "$DISPLAY_COUNT" -lt 10 ]; then
        echo "SHA1: $sha1"
        cat "$TEMP_DIR/current_sha1_gavs.txt" | sed 's/^/  GAV: /'
        echo ""
        DISPLAY_COUNT=$((DISPLAY_COUNT + 1))
    fi
done

if [ "$DIFF_COUNT" -gt 10 ]; then
    echo "... and $((DIFF_COUNT - 10)) more SHA1 values"
fi

# Find SHA1 values in New DB but not in Current DB
echo "SHA1 values in New DB but not in Current DB (excluding GAVs present in both DBs):"
DIFF_COUNT=0
DISPLAY_COUNT=0

comm -13 "$TEMP_DIR/current_sha1_sorted.txt" "$TEMP_DIR/new_sha1_sorted.txt" | while read sha1; do
    # Get GAVs for this SHA1 from New DB
    sqlite3 "$NEW_DB" "SELECT a.group_id || '|' || a.artifact_id || '|' || 
    CASE WHEN instr(i.version, '-') > 0 
         THEN substr(i.version, 1, instr(i.version, '-') - 1) 
         ELSE i.version END AS gav
    FROM indices i JOIN artifacts a ON i.artifact_id = a.id 
    WHERE hex(i.sha1) = '$sha1';" > "$TEMP_DIR/new_sha1_gavs.txt"
    
    # Check if any of these GAVs exist in Current DB
    GAV_IN_BOTH=false
    while read gav; do
        if grep -q "^$gav$" "$TEMP_DIR/current_gavs_sorted.txt"; then
            GAV_IN_BOTH=true
            break
        fi
    done < "$TEMP_DIR/new_sha1_gavs.txt"
    
    # Skip this SHA1 if any of its GAVs exist in both DBs
    if [ "$GAV_IN_BOTH" = true ]; then
        continue
    fi
    
    # Otherwise, display this SHA1 and its GAVs
    DIFF_COUNT=$((DIFF_COUNT + 1))
    
    # Only show the first 10 items
    if [ "$DISPLAY_COUNT" -lt 10 ]; then
        echo "SHA1: $sha1"
        cat "$TEMP_DIR/new_sha1_gavs.txt" | sed 's/^/  GAV: /'
        echo ""
        DISPLAY_COUNT=$((DISPLAY_COUNT + 1))
    fi
done

if [ "$DIFF_COUNT" -gt 10 ]; then
    echo "... and $((DIFF_COUNT - 10)) more SHA1 values"
fi

# Summary section removed since SHA1 has unique constraint
echo "----------------------------------------"
echo "Comparison completed." 