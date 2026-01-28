rule suspicious_base64_eval {
    meta:
        author = "phishnet-sample"
        description = "detects base64 + eval patterns"
    strings:
        $a = /(?:atob|btoa)\s*\(/
        $b = /eval\s*\(/
        $c = /[A-Za-z0-9+\/]{40,}={0,2}/
    condition:
        ($a and $b) or $c
}
