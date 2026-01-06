# 1. Create directory structure
mkdir log-parser-project
cd log-parser-project

# 2. Add your files
cp /path/to/log_parser.py .
cp /path/to/grader.py .
cp -r /path/to/sample_logs .

# 3. Run the grader
python3 grader.py
```

### Expected Output
```
╔════════════════════════════════════════════════════════════════════╗
║          Apache/Nginx Log Parser - Automated Grader               ║
║                   Week 2 AppSec Exercise                           ║
╚════════════════════════════════════════════════════════════════════╝

======================================================================
                       Checking Required Files
======================================================================

✅ Found log_parser.py
✅ Found sample_logs/ directory
✅ Found 12 log files

[... runs all 8 tests ...]

======================================================================
                          FINAL GRADE REPORT
======================================================================

TOTAL SCORE: 100/100 (100.0%)
LETTER GRADE: A+

🎉 EXCELLENT WORK!
Your parser is production-ready!
