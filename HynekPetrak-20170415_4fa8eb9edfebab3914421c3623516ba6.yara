rule 4fa8eb9edfebab3914421c3623516ba6_js_loader
{
  meta
  description = "Detects samples that share a domain or payload name with malicious downloader+loader sample 4fa8eb9edfebab3914421c3623516ba6 from Hynek Petrak's collection"
  strings:
  $part1 = "meskolz.com"
  $part2 = "cmd.exe /c"
  $part3 = "chro"
  $part4 = "powershell" nocase
  
  $uri1 = "meskolz.com"
  $uri2 = "chro"
  $uri3 = "php"
  condition:
  (all of ($part*)) or (all of ($uri*))
}
