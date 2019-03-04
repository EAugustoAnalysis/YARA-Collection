rule 5601e3f1b386552d309c30661ae3ae30_js_downloader
{
  meta
  description = "Detects samples that share a domain or payload name with malicious js downloader sample 4fa8eb9edfebab3914421c3623516ba6 from Hynek Petrak's collection"
  strings:
  $dom1 = "corporationregistry-online-form.com"
  $dom2 = "singoutloudkaraoke.com"
  
  $uri1 = "zXMd7WmsfCYR4Elijowfndm9BW_vR03h-PFz1zBrfdS7hHp4vENptm70HP17kBhVEZlOn-iXcvg_0"
  $uri2 = "counter/"
  
  $action1 = "Msxml2.XMLHTTP"
  $action2 = "counter/"
  $action3 = "GET"
  $action2 = "response"
  
  condition:
  (all of ($dom*)) or (all of ($uri*)) or (all of ($action*))
}
