import re
from collections import Counter
import pandas as pd
import tmap as tm
from faerun import Faerun
from matplotlib.colors import ListedColormap
import argparse


def preprocess_text(text):
    text = re.sub(r"[^a-zA-Z\s]+", " ", text)
    return [t.lower() for t in text.split() if len(t) > 2]

def main(fingerprint_file):
    df = pd.read_csv(fingerprint_file)
    df.drop(df.tail(1).index, inplace=True)

    enc = tm.Minhash(4096)
    lf = tm.LSHForest(d=4096, l=128)

    ctr = Counter()
    texts = []
    
    for _, row in df.iterrows():
        try:
            text = preprocess_text(row["filtered_http_headers"])
            ctr.update(text)
            texts.append(text)
        except Exception as e:
            print(f"Error processing row: {e}")

    df['host'] = df['server_name']
    n =  0 #unused atm but used for removing the n most common headers set to zero to keep all headers
    common_words = [word for word, _ in ctr.most_common()[:n]]
    all_words = {word: i for i, (word, _) in enumerate(ctr.items())}

    fingerprints = []
    for text in texts:
        fingerprint = []
        for word in text:
            if word not in common_words:
                fingerprint.append(all_words[word])
        fingerprints.append(tm.VectorUint(fingerprint))

    if not fingerprints:
        print("No fingerprints created. Check the input data and preprocessing steps.")
        return

    lf.batch_add(enc.batch_from_sparse_binary_array(fingerprints))
    lf.index()

    config = tm.LayoutConfiguration()
    config.k = 50
    x, y, s, t, _ = tm.layout_from_lsh_forest(lf, config=config)

    print(f"Length of x: {len(x)}")
    print(f"Length of y: {len(y)}")

    faerun = Faerun(
        view="front", coords=False, legend_title="", legend_number_format="{:.0f}"
    )

    combined_labels = [f"{header_hash} {label}" for header_hash, label in zip(df["filtered_http_headers_hash"], df["host"])]
    colors = ['lime','red']
    custom_colormap = ListedColormap(colors)
    
    labels = df['label'].tolist()
    numeric_labels = [int(label) for label in labels]
    faerun = Faerun(clear_color="#ffffff", view="front", coords=False)
    faerun.add_scatter(
        "HTTP",
        {"x": x, "y": y, "c": numeric_labels, "labels": combined_labels},
        shader="smoothCircle",
        colormap=custom_colormap,
        point_scale=1,
        max_point_size=10,
    )


    faerun.add_tree(
        "HTTP_tree", {"from": s, "to": t}, point_helper="HTTP", color="#666666"
    )

    faerun.plot("HTTP_Headers")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a Faerun plot from a fingerprint file.")
    parser.add_argument("-f","--fingerprints_file", type=str, default="own_scans/cf_master_fingerprint.csv", help="File containing the fingerprints")
    args = parser.parse_args()

    main(args.fingerprints_file)
