Set-Location $PSScriptRoot
Write-Host "DNS Tunneling and Malicious DNS Behaviour Detection System"
Write-Host "Starting live detector..."
python ".\scripts\dns_detector.py"
