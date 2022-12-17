rule EmailPhishing {

meta:
  author = "Grupo 10 - USACH"
  date= "18-12-2022"
  description = "Desarrollada para Evaluación Final"

strings:
  $eml_1="From:"
  $eml_2="To:"
  $eml_3="Subject:"

  $saludo_1="Hola sr/sra" nocase 
  $saludo_2="Hello sir/madam" nocase
  $saludo_3="Atencion" nocase
  $saludo_4="Attention" nocase
  $saludo_5="Dear user" nocase
  $saludo_6="Account holder" nocase

  $key1 = "BTC" nocase
  $key2 = "Wallet" nocase
  $key3 = "Bitcoin" nocase
  $key4 = "hours" nocase
  $key5 = "payment" nocase
  $key6 = "malware" nocase
  $key = "bitcoin address" nocase
  $key7 = "access" nocase
  $key8 = "virus" nocase

  $url_1="Click" nocase
  $url_2="Confirm" nocase
  $url_3="Verify" nocase
  $url_4="Here" nocase
  $url_5="Now" nocase
  $url_6="Change password" nocase 

  $lie_1="Unauthorized" nocase
  $lie_2="Expired" nocase
  $lie_3="Deleted" nocase
  $lie_4="Suspended" nocase
  $lie_5="Revoked" nocase
  $lie_6="Unable" nocase
 
condition:
  all of ($eml*) and
  any of (($saludo* or ($key*) or ($url*) or ($lie*))
}
