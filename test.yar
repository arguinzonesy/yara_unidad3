rule Archivo_Sospechoso {

meta:
  author = "Grupo 10 - USACH"
  date= "18-12-2022"
  description = "Busca Patrones de Archivos con VBA y que contengan codificación Base64"

strings:
  $officemagic = { D0 CF 11 E0 A1 B1 1A E1 }
  $zipmagic = "PK"
  $97str1 = "_VBA_PROJECT_CUR" wide
  $97str2 = "VBAProject"
  $97str3 = { 41 74 74 72 69 62 75 74 00 65 20 56 42 5F }
  $xmlstr1 = "vbaProject.bin"
  $xmlstr2 = "vbaData.xml"
  $mime = "MIME-Version:"
  $base64 = "Content-Transfer-Encoding: base64"
  $mso = "Content-Type: application/x-mso"
  $activemime = /Q(\x0D\x0A|)W(\x0D\x0A|)N(\x0D\x0A|)0(\x0D\x0A|)a(\x0D\x0A|)X(\x0D\x0A|)Z(\x0D\x0A|)l(\x0D\x0A|)T(\x0D\x0A|)W/

condition:
  ($officemagic at 0 and any of ($97str*)) or ($zipmagic at 0 and any of ($xmlstr*)) and ($mime at 0 and $base64 and $mso and $activemime)
}
