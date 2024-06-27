from math import e, exp
import pandas as pd
import argparse
import re
import tmap as tm
from sklearn.preprocessing import StandardScaler
from faerun import Faerun
from matplotlib.colors import ListedColormap
from collections import Counter


def preprocess_text(text):
    pattern = r"(?<!Server:)[^a-zA-Z0-9\s:/\(\)\.-]+"
    ts = re.sub(pattern, " ", text)
    return [t for t in ts.split() if len(t) > 2]

def process_headers(headers):
    ctr = Counter()
    texts = []
    for row in headers:
        try:
            text = preprocess_text(row)
            ctr.update(text)
            texts.append(text)
        except Exception as e:
            texts.append(['error'])
            #print(f"Error processing row: {e}, {row}")
    
    n =  0 #unused atm but used for removing the n most common headers set to zero to keep all headers
    common_words = [word for word, _ in ctr.most_common()[:n]]
    all_words = {word: i for i, (word, _) in enumerate(ctr.items())}
    all_words['error'] = 9999
    fingerprints = []
    for text in texts:
        fingerprint = []
        for word in text:
            if word not in common_words:
                fingerprint.append(all_words[word])
        fingerprint_str = "_".join(map(str, fingerprint))        
        fingerprints.append(fingerprint_str)

    if not fingerprints:
        print("No fingerprints created. Check the input data and preprocessing steps.")
        return
    
    return fingerprints


def main(fingerprint_file, include_headers):
    data = pd.read_csv(fingerprint_file)
    server_names = data['server_name'].tolist()
    ip = data['ip'].tolist()
    labels = data['label'].tolist()
    fp = data['final_fp'].tolist()
    as_values = data['AS'].tolist()

    if include_headers:
        header_fp = process_headers(data['filtered_http_headers'])

        data['headers_str'] = header_fp
    
    data = data.drop(['ip', 'server_name', 'input_list', 'label', 'AS', 'fingerprint','http_headers','filtered_http_headers','filtered_http_headers_hash', 'final_fp'], axis=1)
  
    max_lengths = {}

    for column in data.columns:
        max_lengths[column] = data[column].apply(lambda x: len(str(x).split('_')) if isinstance(x, str) else 1).max()

    for column in data.columns: 
        try:
            data[column] = data[column].apply(lambda x: [int(i) if i.isdigit() else float(i) for i in re.split('_|-', str(x))] if isinstance(x, str) else [x])
            data[column] = data[column].apply(lambda x: x + [0] * (max_lengths[column] - len(x)))
        except Exception as e:
            print(f"Error processing column: {e}")

    expanded_data = pd.concat([pd.DataFrame(data[col].tolist()).add_prefix(f"{col}_") for col in data.columns], axis=1)

    expanded_data.to_csv('output.csv', index=False)
    scaler = StandardScaler()
    numeric_columns = expanded_data.select_dtypes(include=['float64', 'int64']).fillna(0).astype(float)

    data_points = scaler.fit_transform(numeric_columns)

    dims = 2048
    enc = tm.Minhash(dims, 42)
    lf = tm.LSHForest(d=dims, l=128)

    data_points_list = [dp.tolist() for dp in data_points]
    minhash_signatures = [enc.from_weight_array(dp) for dp in data_points_list]

    lf.batch_add((minhash_signatures))
    
    lf.index()
    config = tm.LayoutConfiguration()
    config.k = 100


    x, y, s, t, _ = tm.layout_from_lsh_forest(lf, config=config)
 

    numeric_labels = [int(label) for label in labels]
    combined_labels = [f"{as_value} {label} {server_name}_{ip} {fp}" for as_value, label, server_name, fp, ip in zip(as_values, labels, server_names, fp, ip)]

    colors = ['lime','red','blue']
    custom_colormap = ListedColormap(colors)

    faerun = Faerun(clear_color="#ffffff", view="front", coords=False)
    faerun.add_scatter(
        "weighted",
        {"x": x, "y": y, "c": numeric_labels, "labels": combined_labels},
        shader="smoothCircle",
        colormap=custom_colormap,
        interactive=True,
        point_scale=2,
        max_point_size=10,
    )

    faerun.add_tree(
        "server_data_tree", {"from": s, "to": t}, point_helper="weighted", color="#666666"
    )
    faerun.plot("weighted")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a Faerun plot from a fingerprint file.")
    parser.add_argument("-f","--fingerprints_file", type=str, default="own_scans/cf_master_fingerprint.csv", help="File containing the fingerprints")
    parser.add_argument("-c","--include_headers", action="store_true", help="Includes headers")
    args = parser.parse_args()

    main(args.fingerprints_file, args.include_headers)



# enc = tm.Minhash(2048)
#     data_points_list = [dp.tolist() for dp in data_points]
#     minhash_signatures = [enc.from_weight_array(dp) for dp in data_points_list]
#     lf = tm.LSHForest(d=2048, l=32)

#     print(minhash_signatures)
#     for signature in minhash_signatures:
#         lf.add(signature)

#     lf.index()
#     config = tm.LayoutConfiguration()
#     config.k = 200
