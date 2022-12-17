rule Conexiones_Sospechosas {

meta:
  author = "Grupo 10 - USACH"
  date = "18-12-2022"
  description = "Busca conexiones sospechosas en capturas de trafico PCAP"

strings:
  $ip1 = "13.107.42.13"
  $ip2 = "64.188.19.241"
  $ip3 = "104.223.119.167"
  $ip4 = "79.134.225.79"  

  $url1 ="http://64.188.19.241/atcn.jpg"
  $url2 ="http://104.223.119.167/calient.jpg"
  $url3 ="shiestynerd.dvrlists.com"  

condition:
  any of them
}
