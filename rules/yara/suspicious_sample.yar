rule CyberNova_Suspicious_Sample
{
    meta:
        description = "Detects suspicious indicators in a safe analysis sample"
        author = "CYBERNOVA AI"
        reference = "CyberNova Threat Hunting Toolkit"
        severity = "medium"

    strings:
        $s1 = "PowerShell execution detected"
        $s2 = "Possible credential theft behavior"

    condition:
        2 of them
}
