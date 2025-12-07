#!/bin/bash

echo "Testing fixed analyze endpoint..."

# Test the analyze endpoint
echo "1. Testing /analyze endpoint:"
curl -X POST http://localhost:8000/analyze -F "file=@/home/shinichi/Documents/VSC/vestigo-data/builds/tinycrypt_aes_decrypt_arm64_O2.o" > analyze_response.json 2>/dev/null

if [ $? -eq 0 ]; then
    echo "✅ /analyze endpoint successful"
    echo "   Data collection status:"
    cat analyze_response.json | jq '.data_collection' 2>/dev/null || echo "   - No data_collection field"
    
    # Extract job ID for further testing
    JOB_ID=$(cat analyze_response.json | jq -r '.jobId' 2>/dev/null)
    echo "   Job ID: $JOB_ID"
    
    # Test complete analysis endpoint
    echo ""
    echo "2. Testing /job/{job_id}/complete-analysis endpoint:"
    curl -X GET "http://localhost:8000/job/$JOB_ID/complete-analysis" > complete_response.json 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo "✅ /complete-analysis endpoint successful"
        echo "   Summary:"
        cat complete_response.json | jq '.summary' 2>/dev/null || echo "   - No summary field"
    else
        echo "❌ /complete-analysis endpoint failed"
    fi
    
else
    echo "❌ /analyze endpoint failed"
fi

echo ""
echo "3. Checking server logs for errors..."
echo "(Check terminal output for any error messages)"

# Cleanup
rm -f analyze_response.json complete_response.json

echo ""
echo "Testing complete!"