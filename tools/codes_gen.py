import pandas as pd
import json

def main():
    df = pd.read_csv('cvss_vector_string_metadata.csv')
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

    with open('..\cvss\cvss_guide.json', 'w') as f:
        f.write(json.dumps(new,indent=2))

if __name__ == "__main__":
    main()