rule EmailPhishing {

meta:
  author = "Grupo 10 - USACH"
  date= "18-12-2022"
  description = "Desarrollada para Evaluación Final"

strings:
  $eml_1="From:"
  $eml_2="To:"
  $eml_3="Subject:"

  $hi_1="Hola sr/sra" nocase 
  $hi_2="Hello sir/madam" nocase
  $hi_3="Atencion" nocase
  $hi_4="Attention" nocase
  $hi_5="Dear user" nocase
  $hi_6="Account holder" nocase

  $key_1 = "BTC" nocase
  $key_2 = "Wallet" nocase
  $key_3 = "Bitcoin" nocase
  $key_4 = "hours" nocase
  $key_5 = "payment" nocase
  $key_6 = "malware" nocase
  $key_7 = "bitcoin address" nocase
  $key_8 = "access" nocase
  $key_9 = "virus" nocase

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
  any of ($hi*) and 
  any of ($key*) or 
  any of ($url*) or 
  any of ($lie*)
}
