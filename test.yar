rule Archivo_Sospechoso {

meta:
  author = "Grupo 10 - USACH"
  date= "18-12-2022"
  description = "Busca Patrones de Archivos con VBA sospechosos"

strings:
  $officemagic = { D0 CF 11 E0 A1 B1 1A E1 }
  $zipmagic = "PK"
  $vba1 = "_VBA_PROJECT_CUR" wide
  $vba2 = "VBAProject"
  $vba3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F }
  $xmlstr1 = "vbaProject.bin"
  $xmlstr2 = "vbaData.xml"
  $string1 = "[Content_Types].xml"

condition:
  ($officemagic at 0 and any of ($vba*)) or ($zipmagic at 0 and any of ($xmlstr*) or $string1)
}
