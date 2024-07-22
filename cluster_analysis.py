import numpy as np
import matplotlib.pyplot as plt
import random


def get_sorted_neighbors(lsh_forest, query_index, k=10):
    """
    Get k-nearest neighbors sorted by similarity score.

    Args:
        lsh_forest: TMAP LSH Forest object
        query_index: Index of the query point
        k: Number of neighbors to retrieve - default 10
    
    Returns: 
        Sorted list of (similarity, index) tuples
    """
    neighbors = lsh_forest.query_linear_scan_by_id(query_index, k)
    return sorted(neighbors, key=lambda x: x[0])


def analyze_neighbors(lsh_forest, tls_data, query_index, k=10):
    """
    Analyze the k-nearest neighbors of a query index in the LSH Forest.
    
    Args:
        lsh_forest: TMAP LSH Forest object
        tls_data: DataFrame containing TLS fingerprints
        query_index: Index of the query point
        k: Number of neighbors to retrieve - default 10
        
    Returns:
        None
    """
    sorted_neighbors = get_sorted_neighbors(lsh_forest, query_index, k)
    
    print(f"Analysis of {k} nearest neighbors for query index {query_index}:")
    print(f"Query TLS Fingerprint: {tls_data.iloc[query_index]}\n")
    
    for similarity, neighbor_index in sorted_neighbors:
        print(f"Neighbor Index: {neighbor_index}")
        print(f"Similarity Score: {similarity:.4f}")
        print(f"{tls_data.iloc[neighbor_index]['server_name']}")
        print(f"{tls_data.iloc[neighbor_index]['fingerprint']}")
        print(f"{tls_data.iloc[neighbor_index]['final_fp']}")
        print(f"{tls_data.iloc[neighbor_index]['version']} {tls_data.iloc[neighbor_index]['ciphers']}")
        print(f"{tls_data.iloc[neighbor_index]['ext']} {tls_data.iloc[neighbor_index]['enc_ext']}")
        print(f"{tls_data.iloc[neighbor_index]['cert_ext']} {tls_data.iloc[neighbor_index]['alerts']}")

    similarities = [score for score, _ in sorted_neighbors[1:]]
    print(f"Average Similarity: {np.mean(similarities):.4f}")
    print(f"Similarity Distance Range: {min(similarities):.4f} to {max(similarities):.4f}")

def plot_similarity_scores(df, lsh_forest, data_set, num_samples=20, k=10, filename='similarity_scores'):
    """
    Plot the similarity scores of the k-nearest neighbors for a random sample of the dataset.
    This enables us to examine the distribution of similarity scores for the LSH Forest
    and the stability and accuracy of the k-c-NN graph.

    Args:
        df: DataFrame containing TLS fingerprints
        lsh_forest: TMAP LSH Forest object
        data_set: Name of the dataset
        num_samples: Number of random samples to plot - default 20
        k: Number of neighbors to retrieve - default 10
        filename: Name of the output file - default 'similarity_scores'
    
    Returns:
        None - Create a file on disk with the plot named 'filename_{data_set}.png'
            deafult filename is 'similarity_scores_data_set.png'
    """    
    random_ids = random.sample(range(len(df)), num_samples)
    plt.style.use('_mpl-gallery')
    plt.figure(figsize=(10, 6))

    for id in random_ids:
        neighbors = get_sorted_neighbors(lsh_forest, id, k)
        scores = [score for score, _ in neighbors] 
        plt.plot(range(1, k+1), scores, marker='o', label=f"{df.iloc[id]['ip']}") 
        

    plt.xlabel("Neighbor Rank")
    plt.ylabel("LSH Forest Score")
    plt.title(f"LSH Forest Scores for {num_samples} Random Samples in Dataset {data_set}")
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()
    plt.savefig(f"{filename}_{data_set}.png", dpi=300, bbox_inches='tight')
    plt.close()

def plot_fingerprint_comparison(data, data_set, filename='fingerprint_comparison'):
    """
    Plot the comparison of unique fingerprints for each input list in the dataset.
    This allows us to example the fingerprint granularity of the ActiveTLS and 
    Enriched fingerprints.

    Args:
        data: DataFrame containing TLS fingerprints
        data_set: Name of the dataset
        filename: Name of the output file - default 'fingerprint_comparison'

    Returns:
        None - Creates a file on disk with the plot named 'filename_data_set.png'
            deafult filename is 'fingerprint_comparison_{data_set}.png'
    """
    grouped = data.groupby('input_list').agg({
        'fingerprint': lambda x: len(set(x)),
        'final_fp': lambda x: len(set(x))
    }).reset_index()

    plt.figure(figsize=(14, 6))  
    bar_width = 0.35 
    index = np.arange(len(grouped))
    r1 = index - bar_width/2
    r2 = index + bar_width/2

    plt.bar(r1, grouped['fingerprint'], color='#f9a65a', width=bar_width, label='ActiveTLS Fingerprint')
    plt.bar(r2, grouped['final_fp'], color='#599ad3', width=bar_width, label='Enriched Fingerprint')

    plt.xlabel("Input List")
    plt.ylabel("Number of Unique Fingerprints")
    plt.title(f"Comparison of Unique Fingerprints by Input List For {data_set}")
    plt.xticks(index, grouped['input_list'])

    plt.legend()

    max_value = max(grouped['fingerprint'].max(), grouped['final_fp'].max())
    plt.ylim(0, max_value * 1.1)  

    for i, (atls, enriched) in enumerate(zip(grouped['fingerprint'], grouped['final_fp'])):
        increase = (enriched - atls) / atls * 100
        plt.text(r1[i], atls, str(atls), ha='center', va='bottom')
        plt.text(r2[i], enriched, str(enriched), ha='center', va='bottom')
        
        higher_bar = max(atls, enriched)
        plt.text(index[i], higher_bar + 5, f'+{increase:.1f}%', ha='center', va='bottom')

    plt.tight_layout()
    plt.savefig(f"{filename}_{data_set}.png", dpi=300, bbox_inches='tight')
    plt.close()