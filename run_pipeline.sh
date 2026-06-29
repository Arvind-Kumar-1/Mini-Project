#!/bin/bash

echo "🚀 Starting the full DPI analysis pipeline..."
echo "========================================="

# --- STAGE 1: Run the ML Signature Generation ---
echo "🔬 Stage 1: Running ML-based signature generation (v3.py)..."
python3 v3.py

# Check if Stage 1 was successful before proceeding
if [ $? -eq 0 ]; then
    echo "✅ Stage 1 complete."
    echo "-----------------------------------------"

    # --- STAGE 2: Run the Automated Signature Merge Tool ---
    echo "🤖 Stage 2: Running automated verification and merge (merge_tool.py)..."
    python3 merge_tool.py

    # Check if Stage 2 was successful
    if [ $? -eq 0 ]; then
        echo "✅ Stage 2 complete."
        echo "-----------------------------------------"

        # --- STAGE 3: Run the LLM Refinement and Discovery ---
        echo "🧠 Stage 3: Running LLM-based refinement and discovery (dpi_llm_pipeline.py)..."
        python3 dpi_llm_pipeline.py

        # Check if Stage 3 was successful
        if [ $? -eq 0 ]; then
            echo "✅ Stage 3 complete."
            echo "-----------------------------------------"
            echo "🎉 Full pipeline finished successfully!"
        else
            echo "❌ Stage 3 (dpi_llm_pipeline.py) failed. Aborting."
            exit 1
        fi
    else
        echo "❌ Stage 2 (merge_tool.py) failed. Aborting."
        exit 1
    fi
else
    echo "❌ Stage 1 (v3.py) failed. Aborting."
    exit 1
fi