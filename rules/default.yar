rule executable_pe {
    meta:
        description = "Windows PE executable detected"
        severity = "high"
        category = "executable"
    condition:
        uint16(0) == 0x5A4D
}

rule executable_elf {
    meta:
        description = "Linux ELF executable detected"
        severity = "high"
        category = "executable"
    condition:
        uint32(0) == 0x464C457F
}

rule executable_macho {
    meta:
        description = "macOS Mach-O executable detected"
        severity = "high"
        category = "executable"
    condition:
        uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or uint32(0) == 0xBEBAFECA
}

rule suspicious_polyglot {
    meta:
        description = "Potential polyglot file - multiple format signatures detected"
        severity = "high"
        category = "evasion"
    strings:
        $zip = "PK\x03\x04"
    condition:
        uint16(0) == 0x5A4D and $zip
}

rule suspicious_office_macro_autoopen {
    meta:
        description = "Office document with suspicious auto-execute macro patterns"
        severity = "medium"
        category = "macro"
    strings:
        $autoopen = "AutoOpen" nocase wide
        $autoexec = "AutoExec" nocase wide
        $autoclose = "AutoClose" nocase wide
        $documentopen = "Document_Open" nocase wide
        $workbookopen = "Workbook_Open" nocase wide
        $shell = "Shell" nocase wide
        $wscript = "WScript.Shell" nocase wide
        $powershell = "PowerShell" nocase wide
        $cmd = "cmd.exe" nocase wide
    condition:
        any of ($autoopen, $autoexec, $autoclose, $documentopen, $workbookopen)
        and any of ($shell, $wscript, $powershell, $cmd)
}

rule suspicious_script_obfuscation {
    meta:
        description = "Script with obfuscation patterns"
        severity = "medium"
        category = "script"
    strings:
        $eval = "eval" nocase
        $fromcharcode = "fromCharCode" nocase
        $unescape = "unescape" nocase
        $atob = "atob" nocase
        $btoa = "btoa" nocase
        $exec = "exec" nocase
        $spaw_n = "spawn" nocase
        $charcode_pattern = /\\x[0-9a-fA-F]{2}/
        $unicode_pattern = /\\u[0-9a-fA-F]{4}/
    condition:
        3 of them
}

rule suspicious_php_webshell {
    meta:
        description = "Potential PHP webshell patterns"
        severity = "critical"
        category = "webshell"
    strings:
        $base64_decode = "base64_decode" nocase
        $eval = "eval" nocase
        $system = "system(" nocase
        $passthru = "passthru" nocase
        $shell_exec = "shell_exec" nocase
        $exec = "exec(" nocase
        $popen = "popen" nocase
        $proc_open = "proc_open" nocase
        $_get = "$_GET" nocase
        $_post = "$_POST" nocase
        $_request = "$_REQUEST" nocase
    condition:
        any of ($base64_decode, $eval, $system, $passthru, $shell_exec, $exec, $popen, $proc_open)
        and any of ($_get, $_post, $_request)
}

rule suspicious_jsp_webshell {
    meta:
        description = "Potential JSP webshell patterns"
        severity = "critical"
        category = "webshell"
    strings:
        $runtime = "Runtime.getRuntime()" nocase
        $exec = ".exec(" nocase
        $processbuilder = "ProcessBuilder" nocase
        $getparameter = "getParameter" nocase
        $scriptengine = "ScriptEngine" nocase
    condition:
        any of ($runtime, $processbuilder, $scriptengine) and $exec
        or (any of ($runtime, $processbuilder) and $getparameter)
}

rule suspicious_asp_webshell {
    meta:
        description = "Potential ASP webshell patterns"
        severity = "critical"
        category = "webshell"
    strings:
        $wscript_shell = "WScript.Shell" nocase
        $cmd_exe = "cmd.exe" nocase
        $shell_execute = "ShellExecute" nocase
        $execute = "Execute(" nocase
        $eval = "Eval(" nocase
        $request_form = "Request.Form" nocase
        $request_querystring = "Request.QueryString" nocase
    condition:
        any of ($wscript_shell, $shell_execute, $execute, $eval)
        and any of ($cmd_exe, $request_form, $request_querystring)
}

rule suspicious_archive_bomb {
    meta:
        description = "Potential archive bomb - high compression ratio indicators"
        severity = "medium"
        category = "archive"
    strings:
        $zip = "PK\x03\x04"
        $rar = "Rar!\x1a\x07"
    condition:
        filesize < 1MB and (
            (#zip > 100) or (#rar > 10)
        )
}

rule suspicious_embedded_exe {
    meta:
        description = "Embedded executable inside another file"
        severity = "high"
        category = "embedded"
    strings:
        $mz = "MZ"
        $pe = "PE\x00\x00"
    condition:
        not uint16(0) == 0x5A4D and $mz and $pe
}

rule suspicious_double_extension {
    meta:
        description = "Double extension trick (e.g., document.pdf.exe)"
        severity = "medium"
        category = "social_engineering"
    strings:
        $pdf_exe = ".pdf.exe" nocase
        $doc_exe = ".doc.exe" nocase
        $docx_exe = ".docx.exe" nocase
        $xls_exe = ".xls.exe" nocase
        $xlsx_exe = ".xlsx.exe" nocase
        $jpg_exe = ".jpg.exe" nocase
        $png_exe = ".png.exe" nocase
        $txt_exe = ".txt.exe" nocase
    condition:
        any of them
}

rule suspicious_hta_script {
    meta:
        description = "HTA file with suspicious script content"
        severity = "high"
        category = "script"
    strings:
        $hta_header = "<HTA:APPLICATION" nocase
        $wscript = "WScript.Shell" nocase
        $powershell = "PowerShell" nocase
        $cmd = "cmd.exe" nocase
        $shell_execute = "ShellExecute" nocase
    condition:
        $hta_header and any of ($wscript, $powershell, $cmd, $shell_execute)
}

rule suspicious_shortcut_exploit {
    meta:
        description = "LNK file with suspicious parameters"
        severity = "high"
        category = "exploit"
    strings:
        $powershell = "powershell" nocase
        $cmd = "cmd.exe" nocase
        $wscript = "wscript" nocase
        $cscript = "cscript" nocase
        $mshta = "mshta" nocase
    condition:
        uint32(0) == 0x0000004C and any of them
}
