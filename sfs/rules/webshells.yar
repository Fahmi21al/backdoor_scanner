rule Simple_PHP_Webshell {
    meta:
        description = "Detects simple PHP webshells containing system/exec/passthru"
        author = "SFS Scanner"
        severity = "High"
    strings:
        $s1 = "$_GET['cmd']" ascii wide
        $s2 = "$_POST['cmd']" ascii wide
        $s3 = "system(" ascii wide
        $s4 = "shell_exec(" ascii wide
        $s5 = "passthru(" ascii wide
        $test = "SFS_TEST_YARA_PATTERN" ascii wide
    condition:
        any of them
}

rule PHP_B374K_Webshell {
    meta:
        description = "Detects b374k webshell"
        author = "SFS Scanner"
        severity = "Critical"
    strings:
        $s1 = "b374k" nocase ascii wide
        $s2 = "eval(gzinflate(base64_decode(" ascii wide
    condition:
        any of them
}

rule PHP_C99_Webshell {
    meta:
        description = "Detects c99 webshell"
        author = "SFS Scanner"
        severity = "Critical"
    strings:
        $s1 = "c99shell" ascii wide nocase
        $s2 = "c99_update" ascii wide
        $s3 = "c99sh" ascii wide
    condition:
        any of them
}

rule PHP_WSO_Webshell {
    meta:
        description = "Detects WSO webshell"
        author = "SFS Scanner"
        severity = "Critical"
    strings:
        $s1 = "WSOsetcookie" ascii wide
        $s2 = "wso_cmd" ascii wide
        $s3 = "FilesMan" ascii wide
        $s4 = "WSO_VERSION" ascii wide
    condition:
        any of them
}

rule PHP_Obfuscated_Backdoor {
    meta:
        description = "Detects highly obfuscated PHP eval techniques"
        author = "SFS Scanner"
        severity = "High"
    strings:
        $s1 = "eval(base64_decode" ascii wide
        $s2 = "eval(str_rot13(base64_decode" ascii wide
        $s3 = "assert($_" ascii wide
        $s4 = "create_function(" ascii wide
    condition:
        any of them
}

rule WSO_Webshell {
    strings:
        $s1 = "FilesMan" ascii
        $s2 = "WSOsetcookie" ascii
        $s3 = "eval(gzinflate(base64_decode(" ascii
        $s4 = "$GLOBALS['\\x61\\x6e\\x75\\x6e\\x61']" ascii
    condition:
        any of them
}

rule B374k_Webshell {
    strings:
        $s1 = "b374k" ascii wide
        $s2 = "eval(gzinflate(base64_decode(" ascii
        $s3 = "b374k_cookie" ascii
        $s4 = "$b374k" ascii
    condition:
        any of them
}

rule C99_Webshell {
    strings:
        $s1 = "c99shell" ascii wide
        $s2 = "act=cmd" ascii wide
        $s3 = "c999sh" ascii wide
    condition:
        any of them
}

rule Alfa_Webshell {
    strings:
        $s1 = "ALFA TEaM" ascii wide
        $s2 = "Sole Visible" ascii wide
        $s3 = "ALFA_DATA" ascii
    condition:
        any of them
}

rule Crypto_Miner {
    strings:
        $s1 = "stratum+tcp://" ascii wide
        $s2 = "xmr.pool" ascii wide
        $s3 = "xmrig" ascii wide
        $s4 = "cryptonight" ascii wide
    condition:
        any of them
}

rule File_Dropper {
    strings:
        $s1 = "curl_exec" ascii
        $s2 = "wget -O" ascii
        $s3 = "file_put_contents($_SERVER['DOCUMENT_ROOT']" ascii
        $s4 = "file_get_contents('http" ascii
    condition:
        any of them
}

rule Ransomware_Activity {
    strings:
        $s1 = "YOUR FILES ARE ENCRYPTED" ascii wide
        $s2 = "bitcoin address" ascii wide
        $s3 = "pay ransom" ascii wide
        $s4 = "mcrypt_encrypt" ascii
        $s5 = "openssl_encrypt" ascii
    condition:
        any of them
}

rule Generic_Obfuscated_PHP {
    strings:
        $s1 = "$_[]" ascii
        $s2 = "goto" ascii wide
        $s3 = "chr(hexdec(" ascii
        $s4 = "\\x65\\x76\\x61\\x6c" ascii // eval
        $s5 = "base64_decode" ascii
    condition:
        any of them
}

rule PHP_Reverse_Shell {
    meta:
        description = "Detects PHP reverse shells connecting to external servers"
        author = "SFS Scanner"
        severity = "Critical"
    strings:
        $s1 = "fsockopen(" ascii wide
        $s2 = "exec(\"/bin/sh" ascii wide
        $s3 = "system(\"cmd.exe" ascii wide
        $s4 = "proc_open(" ascii wide
    condition:
        any of them
}
