import vs_cvss
import json

test = "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C"

vs = vs_cvss.VectorString(test)
print(json.dumps(vs.to_dict(style="verbose", parentheticals="both"),indent=2))
print(vs.modified_attack_complexity)

