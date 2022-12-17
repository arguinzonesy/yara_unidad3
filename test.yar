/* REGLAS PARA DETECCIÓN DE POTENCIAL RAT REMCOS */

rule Email_Phishing {

meta:
  author = "Grupo 10 - USACH"
  date= "18-12-2022"
  description = "Busca Potencial Email Phishing con Contenido Codificado Base64"

strings:
  $eml_1="From:"
  $eml_2="To:"
  $eml_3="Subject:"

  $key_1 = "BTC" nocase
  $key_2 = "Wallet" nocase
  $key_3 = "Bitcoin" nocase
  $key_4 = "hours" nocase
  $key_5 = "payment" nocase
  $key_6 = "malware" nocase
  $key_7 = "bitcoin address" nocase
  $key_8 = "access" nocase
  $key_9 = "virus" nocase

  $lie_1="Unauthorized" nocase
  $lie_2="Expired" nocase
  $lie_3="Deleted" nocase
  $lie_4="Suspended" nocase
  $lie_5="Revoked" nocase
  $lie_6="Unable" nocase

  $mime = "MIME-Version:"
  $base64 = "Content-Transfer-Encoding: base64"
  $mso = "Content-Type: application/x-mso" 

condition:
  all of ($eml*) and
  (any of ($key*) or  any of ($lie*)) and ($mime at 0 and $base64 and $mso)
}
