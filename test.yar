rule EmailPhishing {

meta:
  author = "Grupo 10 - USACH"
  date= "18-12-2022"
  description = "Desarrollada para Evaluación Final"

strings:
  $eml1="From:"
  $eml2="To:"
  $eml3="Subject:"

  $hi1="Hola sr/sra" nocase 
  $hi2="Hello sir/madam" nocase
  $hi3="Atencion" nocase
  $hi4="Attention" nocase
  $hi5="Dear user" nocase
  $hi6="Account holder" nocase

  $key1 = "BTC" nocase
  $key2 = "Wallet" nocase
  $key3 = "Bitcoin" nocase
  $key4 = "hours" nocase
  $key5 = "payment" nocase
  $key6 = "malware" nocase
  $key7 = "bitcoin address" nocase
  $key8 = "access" nocase
  $key9 = "virus" nocase

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
  any of ($hi*) or 
  any of ($key*) or 
  any of ($url*) or 
  any of ($lie*)
}
