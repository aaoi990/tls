from math import exp
import pandas as pd
import re
import tmap as tm
import numpy as np
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
from faerun import Faerun
from matplotlib.colors import ListedColormap

# Load the data into a DataFrame
data = pd.read_csv('own_scans/correct_scans.csv')

# Save server names for labels and AS column for coloring
server_names = data['ip'].tolist()
labels = data['label'].tolist()
fp = data['fingerprint'].tolist()
as_values = data['AS'].tolist()

# Remove unnecessary columns
data = data.drop(['ip', 'server_name', 'input_list', 'label', 'AS', 'fingerprint'], axis=1)

# Determine the maximum lengths for padding
max_lengths = {}

for column in data.columns:
    max_lengths[column] = data[column].apply(lambda x: len(str(x).split('_')) if isinstance(x, str) else 1).max()

# Split and pad the columns
for column in data.columns:
    data[column] = data[column].apply(lambda x: [int(i) if i.isdigit() else float(i) for i in re.split('_|-', str(x))] if isinstance(x, str) else [x])
    data[column] = data[column].apply(lambda x: x + [0] * (max_lengths[column] - len(x)))

# Flatten the lists into separate columns
expanded_data = pd.concat([pd.DataFrame(data[col].tolist()).add_prefix(f"{col}_") for col in data.columns], axis=1)
print(expanded_data)
# Standardize the numeric data
scaler = StandardScaler()
numeric_columns = expanded_data.select_dtypes(include=['float64', 'int64']).fillna(0).astype(float)
data_points = scaler.fit_transform(numeric_columns)

# Initialize the TMAP Minhash
enc = tm.Minhash()

# Convert data points to lists of floats
data_points_list = [dp.tolist() for dp in data_points]

# Generate Minhash signatures
minhash_signatures = [enc.from_weight_array(dp) for dp in data_points_list]

# Initialize the TMAP LSHForest and add Minhash signatures
lf = tm.LSHForest(d=128, l=32)

for signature in minhash_signatures:
    lf.add(signature)

lf.index()

# Create the layout using layout_from_lsh_forest
x, y, s, t, _ = tm.layout_from_lsh_forest(lf)

# Clip outliers
def clip_outliers(data, z_threshold=3):
    mean = np.mean(data)
    std_dev = np.std(data)
    return np.clip(data, mean - z_threshold * std_dev, mean + z_threshold * std_dev)

x = clip_outliers(x)
y = clip_outliers(y)

# Ensure labels are numeric (0 or 1)
numeric_labels = [int(label) for label in labels]

# Create combined labels for visualization
combined_labels = [f"{as_value} {label} {server_name} {fp}" for as_value, label, server_name, fp in zip(as_values, labels, server_names, fp)]

# Create a custom colormap with 2 distinct colors
colors = ['black','red']
custom_colormap = ListedColormap(colors)

# Visualize using Faerun
faerun = Faerun(clear_color="#FFFFFF", view="front", coords=False)
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





















# from nis import cat
# import pandas as pd
# import tmap as tm
# import numpy as np
# from sklearn.preprocessing import StandardScaler
# import matplotlib.pyplot as plt
# from faerun import Faerun

# # Load the data into a DataFrame
# data = pd.read_csv('updated_data.csv')

# # Save server names for labels and AS column for coloring
# server_names = data['server_name'].tolist()
# labels = data['label'].tolist()
# as_values = data['AS'].tolist()

# # Remove unnecessary columns
# data = data.drop(['ip', 'server_name', 'input_list', 'label', 'AS'], axis=1)


# # Determine the maximum lengths for padding
# max_lengths = {}

# for column in data.columns:
#     max_lengths[column] = data[column].apply(lambda x: len(str(x).split('_')) if isinstance(x, str) else 1).max()

# # Split and pad the columns
# for column in data.columns:
#     data[column] = data[column].apply(lambda x: [int(i) for i in str(x).split('_')] if isinstance(x, str) else [x])
#     data[column] = data[column].apply(lambda x: x + [0] * (max_lengths[column] - len(x)))

# # Flatten the lists into separate columns
# expanded_data = pd.concat([pd.DataFrame(data[col].tolist()).add_prefix(f"{col}_") for col in data.columns], axis=1)

# print(expanded_data)
# # # Standardize the numeric data
# scaler = StandardScaler()
# numeric_columns = expanded_data.select_dtypes(include=['float64', 'int64']).fillna(0).astype(float)
# data_points = scaler.fit_transform(numeric_columns)

# # # Initialize the TMAP Minhash
# enc = tm.Minhash()

# # # Convert data points to lists of floats
# data_points_list = [dp.tolist() for dp in data_points]

# # # Generate Minhash signatures
# minhash_signatures = [enc.from_weight_array(dp) for dp in data_points_list]

# # # Initialize the TMAP LSHForest and add Minhash signatures
# lf = tm.LSHForest(d=128, l=32)

# for signature in minhash_signatures:
#     lf.add(signature)

# lf.index()

# # # Create the layout using layout_from_lsh_forest
# x, y, s, t, _ = tm.layout_from_lsh_forest(lf)

# # # Clip outliers
# def clip_outliers(data, z_threshold=3):
#     mean = np.mean(data)
#     std_dev = np.std(data)
#     return np.clip(data, mean - z_threshold * std_dev, mean + z_threshold * std_dev)

# x = clip_outliers(x)
# y = clip_outliers(y)

# combined_labels = [f"{as_value} {label}" for as_value, label in zip(as_values, labels)]


# # Convert combined_labels to numeric labels
# label_values = {label: i for i, label in enumerate(set(combined_labels))}
# numeric_labels = [label_values[label] for label in combined_labels]

# from matplotlib.colors import ListedColormap
# # Create a custom colormap with 100 distinct colors
# colors = plt.cm.get_cmap('nipy_spectral', 200)
# custom_colormap = ListedColormap(colors(np.linspace(0, 1, 200)))
# combined_labels = [f"{as_value} {label} {server_name}" for as_value, label, server_name in zip(as_values, labels, server_names)]

# # Visualize using Faerun
# faerun = Faerun(clear_color="#111111", view="front", coords=False)
# faerun.add_scatter(
#     "server_data",
#      {"x": x, "y": y, "c": numeric_labels, "labels": combined_labels},  
#     shader="smoothCircle",
#     colormap=custom_colormap,
#     point_scale=1,
#     max_point_size=10,
# )

# faerun.add_tree(
#     "server_data_tree", {"from": s, "to": t}, point_helper="server_data", color="#666666"
# )
# faerun.plot("server_data")
