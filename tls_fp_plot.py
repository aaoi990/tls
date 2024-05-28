from math import exp
import pandas as pd
import argparse
import re
import tmap as tm
import numpy as np
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
from faerun import Faerun
from matplotlib.colors import ListedColormap


def main(fingerprint_file):
    data = pd.read_csv(fingerprint_file)

    server_names = data['server_name'].tolist()
    labels = data['label'].tolist()
    fp = data['fingerprint'].tolist()
    as_values = data['AS'].tolist()

    data = data.drop(['ip', 'server_name', 'input_list', 'label', 'AS', 'fingerprint','http_headers','filtered_http_headers', 'filtered_http_headers_hash'], axis=1)

    max_lengths = {}

    for column in data.columns:
        max_lengths[column] = data[column].apply(lambda x: len(str(x).split('_')) if isinstance(x, str) else 1).max()

    for column in data.columns:
        data[column] = data[column].apply(lambda x: [int(i) if i.isdigit() else float(i) for i in re.split('_|-', str(x))] if isinstance(x, str) else [x])
        data[column] = data[column].apply(lambda x: x + [0] * (max_lengths[column] - len(x)))

    expanded_data = pd.concat([pd.DataFrame(data[col].tolist()).add_prefix(f"{col}_") for col in data.columns], axis=1)

    scaler = StandardScaler()
    numeric_columns = expanded_data.select_dtypes(include=['float64', 'int64']).fillna(0).astype(float)
    data_points = scaler.fit_transform(numeric_columns)
    enc = tm.Minhash(2048)
    data_points_list = [dp.tolist() for dp in data_points]
    minhash_signatures = [enc.from_weight_array(dp) for dp in data_points_list]
    lf = tm.LSHForest(d=2048, l=128)

    for signature in minhash_signatures:
        lf.add(signature)

    lf.index()
    config = tm.LayoutConfiguration()
    config.k = 50
    x, y, s, t, _ = tm.layout_from_lsh_forest(lf, config=config)

    def clip_outliers(data, z_threshold=3):
        mean = np.mean(data)
        std_dev = np.std(data)
        return np.clip(data, mean - z_threshold * std_dev, mean + z_threshold * std_dev)

    x = clip_outliers(x)
    y = clip_outliers(y)

    numeric_labels = [int(label) for label in labels]
    combined_labels = [f"{as_value} {label} {server_name} {fp}" for as_value, label, server_name, fp in zip(as_values, labels, server_names, fp)]

    colors = ['lime','red']
    custom_colormap = ListedColormap(colors)

    faerun = Faerun(clear_color="#ffffff", view="front", coords=False)
    faerun.add_scatter(
        "server_data",
        {"x": x, "y": y, "c": numeric_labels, "labels": combined_labels},
        shader="smoothCircle",
        colormap=custom_colormap,
        point_scale=1,
        max_point_size=10,
    )

    faerun.add_tree(
        "server_data_tree", {"from": s, "to": t}, point_helper="server_data", color="#666666"
    )
    faerun.plot("server_data")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a Faerun plot from a fingerprint file.")
    parser.add_argument("-f","--fingerprints_file", type=str, default="own_scans/cf_master_fingerprint.csv", help="File containing the fingerprints")
    args = parser.parse_args()

    main(args.fingerprints_file)
