#!/bin/bash
# Monitor batch processing progress

LOG_FILE="/home/prajwal/Documents/vestigo-data/qiling_analysis/batch_processing.log"

echo "🔍 Monitoring Batch Processing Progress"
echo "========================================"
echo ""

# Check if process is running
if pgrep -f "batch_extract_features.py" > /dev/null; then
    echo "✅ Batch processing is RUNNING"
    echo ""
    
    # Count processed binaries
    PROCESSED=$(grep -c "✅ \[" "$LOG_FILE" 2>/dev/null || echo "0")
    echo "📊 Binaries processed: $PROCESSED / 1100"
    
    # Show last few successes
    echo ""
    echo "📝 Recent completions:"
    grep "✅ \[" "$LOG_FILE" | tail -5
    
    # Show current activity
    echo ""
    echo "🔄 Current activity:"
    tail -10 "$LOG_FILE" | grep -E "(Extracting|Creating|Running|Analyzing)" || echo "Processing..."
    
    # Estimate completion
    if [ "$PROCESSED" -gt 0 ]; then
        # Get elapsed time from log start
        START_TIME=$(stat -c %Y "$LOG_FILE")
        CURRENT_TIME=$(date +%s)
        ELAPSED=$((CURRENT_TIME - START_TIME))
        AVG_TIME=$((ELAPSED / PROCESSED))
        REMAINING=$((1100 - PROCESSED))
        ETA_SECONDS=$((REMAINING * AVG_TIME / 4))  # Divide by 4 for parallel processing
        ETA_MINUTES=$((ETA_SECONDS / 60))
        
        echo ""
        echo "⏱️  Estimated completion: $ETA_MINUTES minutes"
    fi
else
    echo "❌ Batch processing is NOT running"
    echo ""
    
    # Check if it completed
    if grep -q "BATCH EXTRACTION SUMMARY" "$LOG_FILE" 2>/dev/null; then
        echo "✅ Processing COMPLETED!"
        echo ""
        echo "📊 Final Summary:"
        tail -30 "$LOG_FILE" | grep -A 20 "BATCH EXTRACTION SUMMARY"
    else
        echo "⚠️  Processing may have failed or been interrupted"
        echo ""
        echo "Last 10 lines of log:"
        tail -10 "$LOG_FILE"
    fi
fi

echo ""
echo "📁 Output directory: batch_results_full/"
echo "📄 Full log: $LOG_FILE"
