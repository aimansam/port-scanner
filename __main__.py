"""Port scanner CLI entry point."""
import sys
import os

# Add parent to path so absolute imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import main

if __name__ == "__main__":
    main()
