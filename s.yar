import "pe"

rule copyright
{
    meta:
        description = "Detects PE files with specific LegalCopyright strings"

    condition:
        for any i, j in pe.version_info:
            (
                i == "LegalCopyright" and
                (
                    j contains "Copyright (C) 2017, lkmdnbln" or
                    j contains "Copyright (C) 2017, dlfnggfb" or
		    j contains "Copyright (C) 2017, kohichpoxi" or
		    j contains "Copyright (C) 2017, johochpoxx" or
		    j contains "Copyright (C) 2017, kohochpoxi" or
                    j contains "Copyright (C) 2017, alsaggfb" or
		    j contains "Copyright (C) 2017, alsnggfb" or
		    j contains "Copyright (C) 2017, fsrgvieg" or
		    j contains "Copyright (C) 2017, vrtaibtbn" or
		    j contains "Copyright (C) 2017, vcbcnfyj" or
		    j contains "Copyright (C) 2017, vnbnetrirehergbeboebnebne" or
		    j contains "Copyright (C) 2017, fvodijdtb" or
		    j contains "Copyright (C) 2017, dfgndfln"
                )
            )
}

