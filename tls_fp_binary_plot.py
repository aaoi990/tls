from cProfile import label
from operator import ne
import pandas as pd
import re
import os
import argparse
from math import e, exp
import pandas as pd
import argparse
import re
import tmap as tm
from sklearn.preprocessing import StandardScaler
from faerun import Faerun
from matplotlib.colors import ListedColormap
from collections import Counter
from sklearn.preprocessing import MultiLabelBinarizer


def split_and_collect_tls(row, create_header_fp):
    all_values = set()
    columns = ['version', 'ciphers', 'ext', 'enc_ext', 'cert_ext', 'alerts']
    for col in columns:
        if pd.notna(row[col]):
            if isinstance(row[col], str):
                try:
                    all_values.update(row[col].split('_'))
                except AttributeError as e: 
                    all_values.update('none')
            elif isinstance(row[col], float):
                all_values.update([str(row[col])])
            else:
                all_values.update([row[col]])
        
    if create_header_fp:
        try:
            all_values.update(row['filtered_http_headers'].split(' '))
        except Exception as e:
            all_values.update('none')

    return sorted(all_values)

def create_similarity_matrix(vectors):
    server_names = vectors['server_name'].tolist()
    ip = vectors['ip'].tolist()
    labels = vectors['label'].tolist()
    fps = vectors['final_fp'].tolist()
    AS = vectors['AS'].tolist()
    data = vectors.drop(['ip', 'server_name',  'label', 'fingerprint', 'AS', 'final_fp'], axis=1)
    vector_fps = []
    for _, row in data.iterrows():
        vector_fps.append(row.to_list())

    dims = 2048
    enc = tm.Minhash(dims)
    lf = tm.LSHForest(d=dims, l=128)
    minhash_signatures = [enc.from_binary_array(dp) for dp in vector_fps]

    lf.batch_add((minhash_signatures))
    
    lf.index()
    config = tm.LayoutConfiguration()
    config.k = 150
    x, y, s, t, _ = tm.layout_from_lsh_forest(lf, config=config)
    numeric_labels = [int(label) for label in labels]
    combined_labels = [f"{label} {server_name} {ip} {fps[:len(fps)//2]} {fps[len(fps)//2:]} {AS}" for label, server_name, ip, fps, AS in zip( labels, server_names, ip, fps, AS)]

    colors = ['lime','red','blue']
    custom_colormap = ListedColormap(colors)

    faerun = Faerun(clear_color="#ffffff", view="front", coords=False)
    faerun.add_scatter(
        "binary",
        {"x": x, "y": y, "c": numeric_labels, "labels": combined_labels},
        shader="smoothCircle",
        colormap=custom_colormap,
        interactive=True,
        point_scale=2,
        max_point_size=10,
    )

    faerun.add_tree(
        "server_data_tree", {"from": s, "to": t}, point_helper="binary", color="#666666"
    )
    faerun.plot("binary")


def main(fingerprint_file, create_header_fp):
    df = pd.read_csv(fingerprint_file)
    df['fp_breakdown'] = df.apply(lambda row: split_and_collect_tls(row, create_header_fp), axis=1)
    df['fp_breakdown'] = df['fp_breakdown'].apply(lambda x: ' '.join(x))
    print(df['fp_breakdown'])

    unique_entries = set()
    for breakdown in df['fp_breakdown']:
        unique_entries.update(breakdown.split(' '))

    print(len((unique_entries)))

    new_df = pd.DataFrame(columns=list(unique_entries))

    rows = []
    for _, row in df.iterrows():
        row_dict = {entry: 0 for entry in unique_entries}
        fp_breakdown = row['fp_breakdown'].split(' ')
        for entry in fp_breakdown:
            row_dict[entry] = 1
        
        # Add ip and server_name to row_dict
        row_dict['ip'] = row['ip']
        row_dict['server_name'] = row['server_name']
        row_dict['label'] = row['label']
        row_dict['fingerprint'] = row['fingerprint']
        row_dict['final_fp'] = row['final_fp']
        row_dict['AS'] = row['AS']
        rows.append(row_dict)

    new_df = pd.DataFrame(rows)

    # Reorder columns to have 'ip' and 'server_name' first
    column_order = ['ip', 'server_name'] + [col for col in new_df.columns if col not in ['ip', 'server_name']]
    new_df = new_df[column_order]

    create_similarity_matrix(new_df)
    new_filename = os.path.splitext(fingerprint_file)[0]
    new_df.to_csv(f'{new_filename}_vectors.csv', index=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a Faerun plot from a fingerprint file.")
    parser.add_argument("-c","--create_header_fp", action="store_true", help="Launches the header fingerprint creation")
    parser.add_argument("-f","--fingerprints_file", type=str, default="own_scans/cf_master_fingerprint.csv", help="File containing the fingerprints")
    args = parser.parse_args()

    main(args.fingerprints_file, args.create_header_fp)
