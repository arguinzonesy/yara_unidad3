rule IP_Sospechosa {
meta:
  author = "Grupo 10 - USACH"
  date= "18-12-2022"
  description = "Busca Patrones de Archivos con VBA sospechosos"
strings:
  $ipv4 = /([0-9]{1,3}\.){3}[0-9]{1,3}/ wide ascii
condition:
  any of them == 64.188.19.241
}
