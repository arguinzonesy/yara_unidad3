rule IP_Sospechosa {

meta:
  author = "Grupo 10 - USACH"
  date = "18-12-2022"
  description = "Busca Patrones de Archivos con VBA sospechosos"

strings:
  $ip1 = "13.107.42.13"
  $ip2 = "64.188.19.241"

condition:
  any of them
}
