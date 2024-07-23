import pandas as pd
import os
import argparse
import tmap as tm
import pickle
import random
from faerun import Faerun, host
from matplotlib.colors import ListedColormap
from cluster_analysis import analyze_neighbors, plot_fingerprint_comparison, plot_similarity_scores


def split_and_collect_fp(row, create_header_fp):
    """
    Splits the TLS fingerprint and header fingerprint into individual values
    and collects the unique entries.

    Args:
        row (pandas.Series): The row of the fingerprint data.
        create_header_fp (bool): A flag to determine if the http headers should be included.
    
    Returns:
        set: A set of the unique entries in the fingerprint data
    """
    all_values = set()
    columns = ['version', 'ciphers', 'ext', 'enc_ext', 'cert_ext', 'alerts']
    for col in columns:
        if pd.notna(row[col]):
            if isinstance(row[col], str):
                try:
                    all_values.update(row[col].split('_'))
                except AttributeError as e: 
                    all_values.update(['no_tls'])
            elif isinstance(row[col], float):
                all_values.update([str(row[col])])
            else:
                all_values.update([row[col]])
        
    if create_header_fp:
        try:
            all_values.update(row['filtered_http_headers'].split(' '))
        except Exception as e:            
            all_values.update(['no_header'])
    return sorted(all_values)

def create_similarity_matrix(vectors, serve, analysis, fp_data, data_set):
    """
    Creates the minhash and LSF forest and plots the Faerun  graph depending
    on the input requirements.

    Args:
        vectors (pandas.DataFrame): The vector representation of the fingerprint data.
        serve (bool): A flag to determine if the plot should be hosted as an interactive website.
        analysis (bool): A flag to determine if cluster analysis should be conducted.
        fp_data (pandas.DataFrame): The original fingerprint data.
        data_set (str): The name of the fingerprint data set.

    Returns:
        None   
    """
    print(vectors.columns)

    server_names = vectors['server_name'].tolist()
    ip = vectors['ip'].tolist()
    labels = vectors['label'].tolist()
    fps = vectors['final_fp'].tolist()
    AS = vectors['AS'].tolist()
    input = vectors['input_list'].tolist()

    data = vectors.drop(['ip', 'server_name',  'label', 'fingerprint', 'AS', 'final_fp', 'input_list'], axis=1)
    
    vector_fps = []    
    for _, row in data.iterrows():
        vector_fps.append(row.to_list())

    # Dims here can be considered the dimentionality 
    dims = 1024
    enc = tm.Minhash(dims)
    lf = tm.LSHForest(d=dims, l=128, store=True)
    minhash_signatures = [enc.from_binary_array(dp) for dp in vector_fps]
    lf.batch_add((minhash_signatures))    
    lf.index()
    config = tm.LayoutConfiguration()
    config.k = 100

    x, y, s, t, _ = tm.layout_from_lsh_forest(lf, config=config)

    if analysis:
        random_number = random.randint(1, len(fp_data))
        analyze_neighbors(lf, fp_data, random_number, k=10)
        print(fp_data.iloc[random_number]['server_name'])
        plot_fingerprint_comparison(fp_data, data_set)
        plot_similarity_scores(fp_data, lf, data_set)

    numeric_labels = [int(label) for label in labels]
    
    legend_labels = [
        (0, "Known Good Domains"),
        (1, "Known Bad Domains"),
        (2, "Unknown Domains")
    ]

    faerun = Faerun(clear_color="#ffffff", view="front", coords=True)    
         
    static_labels = [
        f"Server Name: {server_name}</br>" 
        f"IP: {ip} </br>"
        f"Fingerprint: </br>"
        f"{fps[:len(fps)//2]} </br>"
        f"{fps[len(fps)//2:]} </br>"
        f"AS: {AS} </br>"
        f"Input Source: {input}" 
        for server_name, ip, fps, AS, input in zip(server_names, ip, fps, AS, input)]
        
    colors = ['#599ad3','red','#f9a65a']
    custom_colormap = ListedColormap(colors)
    faerun.add_scatter(
        "binary",
        {"x": x, "y": y, "c": numeric_labels, "labels": static_labels},
        shader="smoothCircle",
        colormap=custom_colormap,
        interactive=True,
        has_legend=True,
        legend_labels=legend_labels,
        legend_title="Domain Type",
        point_scale=2,
        max_point_size=10
    )

    faerun.add_tree(
        "server_data_tree", {"from": s, "to": t}, point_helper="binary", color="#999999"
    )
    faerun.plot("binary")

    if serve:
        # Specific implemetation for the fearun plot when being run as an
        # interactive web server.
        interactive_labels = [f"{server_name} {ip} {fps[:len(fps)//2]} {fps[len(fps)//2:] }" 
                       for server_name, ip, fps in zip( server_names, ip, fps)]
        
        faerun.add_scatter(
            "binary",
            {"x": x, "y": y, "c": numeric_labels, "labels": interactive_labels},
            shader="smoothCircle",
            colormap="tab10",
            interactive=True,
            has_legend=True,
            legend_labels=legend_labels,
            point_scale=2,
            max_point_size=10
        )

        faerun.plot("binary_interactive")
        def custom_link_formatter(label, index, name):
            labels = label.split(' ')
            print(labels[0], labels[1], labels[2], labels[3])
            link = f"https://www.virustotal.com/gui/domain/{label.split(' ')[0]}"
            if labels[0] == "nan":
                link = f"https://www.virustotal.com/gui/ip-address/{label.split(' ')[1]}"
            return link
    
        def custom_label_formatter(label, index, name):
            labels = label.split(' ')
            final_label = (
                f"Domain: {labels[0]} </br> IP: {labels[1]} </br> "
                f"{labels[2]} </br>"
                f"{labels[3]} </br>") 
            return final_label
        
        with open("binary_bad.fearun", "wb+") as handle:
            pickle.dump(faerun.create_python_data(), handle, protocol=pickle.HIGHEST_PROTOCOL)

        host(
            "binary_bad.fearun",
            label_type="default",
            title="Malicious Hosts",
            link_formatter=custom_link_formatter,
            label_formatter=custom_label_formatter,
            legend=True
        )


def main(fingerprint_file, create_header_fp, serve, analysis):
    """
    Main function to create the Faerun plot from a fingerprint file. 
    Reads the complete fingerprint csv file provided, then splits the TLS
    data from the form of underscore separated strings into a list of individual
    values. The header fingerprints are also split and collected if the create_header_fp
    flag is set. The unique entries are then collected and used to create a vector      
    representation of the data. The vector representation is dynamic, 
    and will create the approriate number of columns based on the TLS features 
    (and the HTTP header features is requested).
    
    Args:
        fingerprint_file (str): The name of the file containing the fingerprints.
        create_header_fp (bool): A flag set to determine if http headers should be
            included in the vectors.
        serve (bool): A flag set to determine if the plot should be hosted
            as an interactive website.
        analysis (bool): A flag set to do conduct similarity and fingerprint analysis.
    
    Returns:    
        None
    """
    df = pd.read_csv(fingerprint_file)
    df['fp_breakdown'] = df.apply(lambda row: split_and_collect_fp(row, create_header_fp), axis=1)

    unique_entries = set()
    for breakdown in df['fp_breakdown']:
        unique_entries.update(breakdown) 

    print(len((unique_entries)))

    rows = []
    for _, row in df.iterrows():
        row_dict = {entry: 0 for entry in unique_entries}
        fp_breakdown = row['fp_breakdown'] 
        for entry in fp_breakdown:
            row_dict[entry] = 1

        row_dict['ip'] = row['ip']
        row_dict['server_name'] = row['server_name']
        row_dict['label'] = row['label']
        row_dict['fingerprint'] = row['fingerprint']
        row_dict['final_fp'] = row['final_fp']
        row_dict['AS'] = row['AS']
        row_dict['input_list'] = row['input_list']
        rows.append(row_dict)

    vector_df = pd.DataFrame(rows)
    column_order = ['ip', 'server_name'] + [col for col in vector_df.columns if col not in ['ip', 'server_name']]
    vector_df[column_order]
    
    data_set_with_ext = os.path.basename(fingerprint_file)
    data_set = os.path.splitext(fingerprint_file)[0]
    vector_df.to_csv(f'{data_set}_vectors.csv', index=False)

    create_similarity_matrix(vector_df, serve, analysis, df, os.path.splitext(data_set_with_ext)[0])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create a Faerun plot from a fingerprint file.")
    parser.add_argument("-c","--create_header_fp", action="store_true", help="Include the http headers in the vectors")
    parser.add_argument("-f","--fingerprints_file", type=str, default="fingerprint.csv", help="File containing the fingerprints")
    parser.add_argument("-s","--serve", action="store_true", help="Host the plot as an interactive website.")
    parser.add_argument("-a","--analysis", action="store_true", help="Conduct fingerprint and similarity analysis.")
   
    args = parser.parse_args()

    main(args.fingerprints_file, args.create_header_fp, args.serve, args.analysis)
