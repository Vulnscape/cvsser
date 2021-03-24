# -*- coding: utf-8 -*-

"""
Guide Generator
~~~~~~~~~~~~~~~~~~~~~
The 'Guide Generator' interprets the contents of the cvss_metadata.csv document,
which outlines the structure, naming conventions, and acceptable values for the various
versions of CVSS vector strings. It generates a cvss_guide.py document which is used
as a source document by the core VS_CVSS library during runtime.

The 'Guide Generator' is merely a convenience for developers of the VS_CVSS module, allowing
CVSS version metadata updates to be more easily maintained. Typical users of the VS_CVSS
module can ignore the contents of the 'tools' directory.

For more on the CVSS specification and CVSS vector strings:
https://www.first.org/cvss/v2/guide
https://www.first.org/cvss/v3.0/specification-document
https://www.first.org/cvss/v3.1/specification-document
"""

import pandas as pd
import json

def main():
    df = pd.read_csv('cvss_metadata.csv')
    di = df.to_dict(orient='records')

    new = {}
    version_list = ["v2.0", "v3.0", "v3.1"]
    for v in version_list:
        for x in di:
            if x[v] == True:
                codes = x["value_codes"].replace("[", "").replace("]", "").split(',')
                names = x["value_names"].replace("[", "").replace("]", "").split(', ')
                if v not in new:
                    new[v] = {}
                new[v][x["metric_code"]] = {}
                new[v][x["metric_code"]]["name"] = x["metric_name"]
                if "values" not in new[v][x["metric_code"]]:
                    new[v][x["metric_code"]]["values"] = {}
                for c,n in zip(codes,names):
                    new[v][x["metric_code"]]["values"][c] = n
                new[v][x["metric_code"]]["type"] = x["type"]
                new[v][x["metric_code"]]["mandatory"] = x["mandatory"]

    with open('../cvsser/cvss_guide.py', 'w') as f:
        f.write(f"""# -*- coding: utf-8 -*-\n\ncvss_guide = {json.dumps(new,indent=2).replace("true","True").replace("false","False")}""")

if __name__ == "__main__":
    main()