@echo off
echo ============================================================
echo Critical Infrastructure Threat Intel - Git Setup
echo ============================================================
echo.

REM Initialize Git repository
echo Initializing Git repository...
git init

REM Add all files
echo Adding files to Git...
git add .

REM Create initial commit
echo Creating initial commit...
git commit -m "Initial commit: Critical Infrastructure Threat Intelligence Framework

- AI-driven threat intelligence for Financial Services and Agriculture sectors
- Aligned with EO 14028, OMB M-22-09, PPD-21, CISA Strategy
- Multi-source threat collection and analysis
- Sector-specific analyzers for compliance
- SIEM/SOAR integration capabilities
- Comprehensive documentation and examples"

echo.
echo ============================================================
echo Git repository initialized successfully!
echo ============================================================
echo.
echo Next steps:
echo 1. Create a new repository on GitHub named: critical-infrastructure-threat-intel
echo 2. Run the following commands:
echo.
echo    git remote add origin https://github.com/segene2001/critical-infrastructure-threat-intel.git
echo    git branch -M main
echo    git push -u origin main
echo.
echo ============================================================
pause
