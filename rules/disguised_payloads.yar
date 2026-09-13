/*
 * Rules for payloads hidden inside other file formats.
 *
 * These complement netscan's structural detector: where the structural checks
 * ask "does this file's shape match its claim?", these ask "does this file
 * contain a specific known-bad pattern?".
 */

rule Script_In_Image_File
{
    meta:
        description = "HTML or script content inside a file served as an image"
        severity = "suspicious"
        reference = "content-sniffing XSS and polyglot delivery"

    strings:
        $png = { 89 50 4E 47 0D 0A 1A 0A }
        $gif = "GIF8"
        $jpg = { FF D8 FF }

        $s1 = "<script" nocase
        $s2 = "<?php" nocase
        $s3 = "<%eval" nocase
        $s4 = "<iframe" nocase

    condition:
        ($png at 0 or $gif at 0 or $jpg at 0) and any of ($s*)
}

rule Archive_With_Single_Executable
{
    meta:
        description = "Small archive whose only content is an executable - the shape of a phishing attachment"
        severity = "suspicious"

    strings:
        // A local file header whose name ends in an executable extension.
        $zip = { 50 4B 03 04 }
        $e1 = ".exe" nocase
        $e2 = ".scr" nocase
        $e3 = ".js" nocase
        $e4 = ".vbs" nocase
        $e5 = ".lnk" nocase
        $e6 = ".hta" nocase

    condition:
        $zip at 0 and filesize < 2MB and any of ($e*)
}

rule LNK_With_Embedded_Command
{
    meta:
        description = "Windows shortcut that launches a shell or script interpreter"
        severity = "malicious"
        reference = "LNK files are a primary initial-access vector"

    strings:
        $header = { 4C 00 00 00 01 14 02 00 }
        $c1 = "powershell" nocase wide ascii
        $c2 = "cmd.exe" nocase wide ascii
        $c3 = "mshta" nocase wide ascii
        $c4 = "rundll32" nocase wide ascii
        $c5 = "wscript" nocase wide ascii
        $c6 = "curl" nocase wide ascii

    condition:
        $header at 0 and any of ($c*)
}

rule OneNote_Embedded_Attachment
{
    meta:
        description = "OneNote section with an embedded file attachment"
        severity = "suspicious"
        reference = "used to bypass Office macro restrictions"

    strings:
        $header = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }
        $embedded = { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC }

    condition:
        $header at 0 and $embedded
}
