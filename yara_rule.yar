/* REGLA DESARROLLADA PARA DETECCIÓN DE .BAT */

rule soy_un_barco{
meta:
  author = "Grupo 10 - USACH"
  date= "05-12-2022"
  description = "Desarrollada para Taller 2 - Unidad 3"
  
strings:
  $a = "format"
  $b = "PPR"
condition:
  $a and $b
}
