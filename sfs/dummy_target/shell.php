<?php
// This is a SAFE dummy file for testing YARA and IOC engines.
// It uses custom non-malicious text strings instead of actual payload signatures
// to prevent false-positive quarantines from Windows Defender/Antivirus.

$yara_trigger = "SFS_TEST_YARA_PATTERN";
$ioc_trigger  = "SFS_TEST_IOC_PATTERN";

echo "Testing SFS Detection Engines...";
echo $yara_trigger;
echo $ioc_trigger;
?>
