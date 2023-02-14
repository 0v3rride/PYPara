c = """
rule XProtect_MACOS_7c241b4
{
    meta:
        description = "MACOS.7c241b4"

    strings:
        $a1 = { 5f 54 72 61 6e 73 66 6f 72 6d 50 72 6f 63 65 73 73 54 79 70 65 }
        $a2 = { 5f 69 6e 66 6c 61 74 65 49 6e 69 74 }
        $b1 = { 90 4? 63 c? 48 8? 0d ?? ?? 00 00 32 14 08 4c 39 fb }
        $b2 = { 49 63 c6 48 8d 0d ?? ?? 00 00 44 32 3c 08 90 48 8b 85 78 ff ff ff 48 3b 45 80 }
        $b3 = { ff cb [0-2] 48 63 c3 48 8b (15 | 0d) ?? ?? 00 (00 | 00 44) 32 ?? ?? 48 8b ?5 [1-4] 48 3b ?5 }
        
    condition:
        Macho and any of ( $a* ) and any of ( $b* )
}
rule XProtect_MACOS_11eaac1
{
    meta:
        description = "MACOS.11eaac1"
    strings:
        $a1 = { 23 21 }
        $b1 = { 74 61 69 6c 20 2b }
        $b2 = { 66 75 6e 7a 69 70 20 2d }
        $b3 = { 6d 6b 74 65 6d 70 20 2d 64 20 2d 74 20 78 }
        $b4 = { 63 68 6d 6f 64 20 2d 52 [0-1] 20 37 35 35 }
        $b5 = { 6b 69 6c 6c 61 6c 6c 20 [0-3] 54 65 72 6d 69 6e 61 6c }
        $b6 = { 6e 6f 68 75 70 20 24 54 4d 50 44 49 52 2f 2a 2e 61 70 70 2f 43 6f 6e 74 65 6e 74 73 2f 4d 61 63 4f 53 2f }
        $c1 = { 50 4b 03 04 0a }
    condition:
        filesize < 500KB and $a1 at 0 and 4 of ($b*) and $c1
}
"""

		

import re

def sDecoder(hString):
	dString = None
	
	try:
		dString = bytes.fromhex(hString).decode("utf-8")
	except:
		dString = False
		
	return dString

rules = {}
meta = {}
strings = {}
condition = None
	
for l in range(0, len(c.split("\n"))):
	
	if len(re.findall("rule", c.split("\n")[l])):
		rule = c.split("\n")[l].split(" ")[1]
		rules.update({rule: {}})
	
	if len(re.findall("description", c.split("\n")[l])):
		meta.update({"description": c.split("\n")[l].strip(" ").split("=")[1]})
		rules[rule].update({"meta": meta})
		
	
	if len(re.findall("strings", c.split("\n")[l])):
		count = 1
		while(re.findall("\$\w?\d?\s=\s", c.split("\n")[l+count])):
			string = " ".join(c.split("\n")[l+count].split(" ")[11:-1]).split(" ")
			dString = sDecoder("".join(string))
			
			if dString:
				strings.update({c.split("\n")[l+count].split(" ")[8]: dString})
			else:
				strings.update({c.split("\n")[l+count].split(" ")[8]: " ".join(string)})
			
			count += 1
			
		rules[rule].update({"strings": strings})
	
	if len(re.findall("condition", c.split("\n")[l])):
		condition = c.split("\n")[l+1].lstrip()
		rules[rule].update({"condition": condition})
	
		
	strings = {}
	
	

print(rules)
