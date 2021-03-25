# cvsser

**cvsser** is a simple library for interpreting CVSS vector strings and converting their metrics into ready-to-publish formats.

```
>>> import cvsser
>>> import json
>>> vs = cvsser.VectorString(test)
>>> print(vs.privileges_required)
N
>>> print(json.dumps(vs.to_dict(style="verbose", parentheticals="both"), indent=2))
{
  "Attack Vector (AV)": "Local (L)",
  "Attack Complexity (AC)": "High (H)",
  "Privileges Required (PR)": "None (N)",
  "User Interaction (UI)": "Required (R)",
  "Scope (S)": "Unchanged (U)",
  "Confidentiality Impact (C)": "High (H)",
  "Integrity Impact (I)": "High (H)",
  "Availability Impact (A)": "High (H)",
  "Exploit Code Maturity (E)": "Unproven (U)",
  "Remediation Level (RL)": "Official Fix (O)",
  "Report Confidence (RC)": "Confirmed (C)",
  "Confidentiality Requirement (CR)": "Not Defined (X)",
  "Integrity Requirement (IR)": "Not Defined (X)",
  "Availability Requirement (AR)": "Not Defined (X)",
  "Modified Attack Vector (MAV)": "Not Defined (X)",
  "Modified Attack Complexity (MAC)": "Not Defined (X)",
  "Modified Privileges Required (MPR)": "Not Defined (X)",
  "Modified User Interaction (MUI)": "Not Defined (X)",
  "Modified Scope (MS)": "Not Defined (X)",
  "Modified Confidentiality (MC)": "Not Defined (X)",
  "Modified Integrity (MI)": "Not Defined (X)",
  "Modified Availability (MA)": "Not Defined (X)"
}
```
