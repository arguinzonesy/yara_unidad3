rule grupo_10 : HL-YA-PP
{
	meta:
		description = "Diseñada para la prueba!"
		threat_level = 10

	strings:
		$a = "format"
		$b = "PPR"
		condition:
		$a and $b
}
