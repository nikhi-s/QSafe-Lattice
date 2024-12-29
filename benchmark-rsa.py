import time
from memory_profiler import memory_usage
import lipsum # for sample text

from memory_profiler import memory_usage
from ast import excepthandler

import numpy as np
import matplotlib.pyplot as plt

import pandas as pd

def measure_memory(func, *args):
    """
    Measure the peak memory usage of a function.

    Parameters:
    -----------
    func : function
        The function whose memory usage is to be measured.
    *args :
        The arguments to be passed to the function being measured.

    Returns:
    --------
    max_memory : float
        The maximum memory usage (in MB) during the execution of the function.

    Example:
    --------
    def example_function(x):
        return x ** 2

    # Measure memory usage of 'example_function'
    peak_memory = measure_memory(example_function, 10)
    print(f"Peak Memory Usage: {peak_memory} MB")
    """
    return memory_usage((func, args), max_usage=True)

def benchmark_rsa(key_size: int, message_size: int):
    """
    Benchmark RSA encryption and decryption performance for a given key size and message size.
    
    Args:
        key_size (int): The size of the RSA key in bits (e.g., 1024, 2048, 4096).
        message_size (int): The size of the message to encrypt in bytes.

    Returns:
        dict: A dictionary containing performance metrics:
            - key_size: Key size used (in bits).
            - message_size: Message size used (in bytes).
            - key_gen_time: Time taken for key generation (in seconds).
            - encryption_time: Time taken for encryption (in seconds).
            - decryption_time: Time taken for decryption (in seconds).
            - key_gen_memory: Memory used for key generation (in MB).
            - ciphertext_size: Size of the encrypted message (in bytes).
            - serialization_time: Time taken for key serialization (in seconds).
    """
    # Measure time for key generation
    start_time = time.time()
    private_key, public_key = generate_rsa_key_pair(key_size)  # RSA key generation
    key_gen_time = time.time() - start_time
    key_gen_memory = measure_memory(generate_rsa_key_pair, key_size)  # Memory usage during key generation

    # Measure time for key serialization
    start_time = time.time()
    serialized_private_key = serialize_key(private_key)  # Serialize private key
    serialization_time = time.time() - start_time
    serialized_public_key = serialize_key(public_key, is_private=False)  # Serialize public key

    # Generate a dummy message with the given message size to encrypt
    str_message = lipsum.generate_words(message_size)[:message_size]
    message = str_message.encode("utf-8")

    try:
        # Measure encryption time
        start_time = time.time()
        encrypted_message = encrypt_message(message, public_key)  # Encrypt the message
        encryption_time = time.time() - start_time
        ciphertext_size = len(encrypted_message)  # Size of the encrypted message

        # Measure decryption time
        start_time = time.time()
        decrypted_message = decrypt_message(encrypted_message, private_key)  # Decrypt the message
        decryption_time = time.time() - start_time
    except Exception as e:
        # In case of an error (e.g., incompatible key size or message size), return partial results
        print(f"Incompatible key size {key_size} or message size {message_size}: {e}")
        return {
            "key_size": key_size,
            "message_size": message_size,
            "key_gen_time": key_gen_time,
            "encryption_time": None,
            "decryption_time": None,
            "key_gen_memory": key_gen_memory,
            "ciphertext_size": None,
            "serialization_time": serialization_time,
        }

    # Return the benchmark results as a dictionary
    return {
        "key_size": key_size,
        "message_size": message_size,
        "key_gen_time": key_gen_time,
        "encryption_time": encryption_time,
        "decryption_time": decryption_time,
        "key_gen_memory": key_gen_memory,
        "ciphertext_size": ciphertext_size,
        "serialization_time": serialization_time,
    }

def collect_benchmark_data(key_sizes, message_sizes, num_samples=10):
    """
    Collect benchmarking data by running the RSA benchmark for different key sizes and message sizes.
    
    Args:
        key_sizes (list): List of RSA key sizes (in bits) to benchmark (e.g., [1024, 2048, 4096]).
        message_sizes (list): List of message sizes (in bytes) to benchmark.
        num_samples (int): Number of samples to collect for each key and message size combination.

    Returns:
        pd.DataFrame: A DataFrame containing the benchmark results with columns for each metric.
    """
    results = []
    for _ in range(num_samples):
        for key_size in key_sizes:
            for message_size in message_sizes:
                result = benchmark_rsa(key_size, message_size)
                results.append(result)

    # Create a pandas DataFrame from the collected results
    df = pd.DataFrame(results)
    return df

def plot_heatmaps(
    all_data,
    key_sizes,
    message_sizes,
    titles,
    save_dir=".",
    annotate_cells=True,
    colormap="viridis"
):
    """
    Generate and save heatmaps for benchmarking data with optional annotations.

    This function generates a heatmap for each metric (e.g., encryption time, decryption time) 
    from the benchmarking data and saves the heatmaps as images in the specified directory.
    
    Parameters:
        all_data (ndarray): 3D array of benchmark data, where each entry represents a metric 
                             for a specific key size and message size. Shape is 
                             (num_metrics, num_key_sizes, num_message_sizes).
        key_sizes (list): List of RSA key sizes (in bits) to be used for the y-axis of the heatmap.
        message_sizes (list): List of message sizes (in characters/bytes) to be used for the x-axis.
        titles (list): List of titles for each benchmark metric (e.g., ["Encryption Time", "Decryption Time"]).
        save_dir (str): Directory path where the heatmap images will be saved. Default is the current directory.
        annotate_cells (bool): If True, annotations with cell values will be added to the heatmap cells.
        colormap (str): The colormap to use for the heatmaps. Default is "viridis". 

    Returns:
        None: The function generates and saves heatmap images for each metric in the specified directory.
    """
    for metric_index, metric_data in enumerate(all_data):
        # Flip the data vertically to have key_sizes in the correct orientation (top to bottom)
        data = np.flipud(metric_data)
        
        # Prepare row and column labels for key sizes and message sizes
        row_labels = [f"{size} bits" for size in key_sizes[::-1]]  # Reverse key_sizes for correct plot orientation
        col_labels = [f"{size} chars" for size in message_sizes]

        # Plot the heatmap
        plt.figure(figsize=(10, 8))
        plt.imshow(data, cmap=colormap, aspect="auto")
        plt.colorbar(label=titles[metric_index])

        # Add axis labels with message sizes on the x-axis and key sizes on the y-axis
        plt.xticks(ticks=np.arange(len(col_labels)), labels=col_labels, rotation=45, ha="right")
        plt.yticks(ticks=np.arange(len(row_labels)), labels=row_labels)

        # Annotate cells with values, if enabled
        if annotate_cells:
            for i in range(data.shape[0]):
                for j in range(data.shape[1]):
                    # Annotate each cell with the formatted data value
                    plt.text(
                        j, i, f"{data[i, j]:.2e}", ha="center", va="center", fontsize=8, color="black"
                    )

        # Add labels for the axes and a title for the heatmap
        plt.xlabel("Message Sizes (chars)")
        plt.ylabel("Key Sizes (bits)")
        plt.title(titles[metric_index])

        # Save the heatmap image with a filename based on the metric title
        plt.tight_layout()
        plt.savefig(f"{save_dir}/{titles[metric_index].replace(' ', '_').lower()}.png")
        plt.show()  # Display the heatmap

def plot_line_charts(df, key_sizes, message_sizes, metric, title):
    """
    Plot line charts for a specific performance metric (e.g., encryption time, memory usage).
    
    Args:
        df (pd.DataFrame): The DataFrame containing the benchmark results.
        key_sizes (list): List of RSA key sizes to plot.
        message_sizes (list): List of message sizes to plot.
        metric (str): The performance metric to plot (e.g., "encryption_time").
        title (str): The title for the plot.

    Returns:
        None: Displays the plot and saves it as a PNG file.
    """
    plt.figure(figsize=(10, 6))
    for key_size in key_sizes:
        # Filter the DataFrame for the current key size
        subset = df[df["key_size"] == key_size]
        # Plot the metric for different message sizes
        plt.plot(
            subset["message_size"],
            subset[metric],
            marker="o",
            label=f"Key Size: {key_size} bits",
        )
    # Customize plot appearance
    plt.title(title)
    plt.xlabel("Message Size (bytes)")
    plt.ylabel("Time (seconds)" if "time" in metric else "Memory (MB)" if "memory" in metric else "Size (bytes)")
    plt.legend()
    plt.grid()
    plt.tight_layout()
    plt.savefig(f"{metric}_line_chart.png")  # Save the plot as a PNG file
    plt.show()  # Display the plot

# Define parameters for benchmarking
num_samples = 10  # Number of benchmark samples to collect
key_sizes = [1024, 2048, 3072, 4096, 8192]  # RSA key sizes in bits
message_sizes = [16, 32, 64, 128, 256, 512, 1024]  # Message sizes in bytes

#message_sizes = [10, 20, 62, 100, 190, 446, 958] # should run the gamut of avg message; add as needed
#1024 bits (128 bytes); Max Bytes = 128 − 66 = 62 bytes (62 characters for ASCII)
#2048 bits (256 bytes); Max Bytes = 256 − 66 = 190 bytes (190 characters for ASCII)
#3072 bits (384 bytes); Max Bytes = 384 − 66 = 318 bytes (318 characters for ASCII)
#4096 bits (512 bytes); Max Bytes = 512 − 66 = 446 bytes (446 characters for ASCII)
#8192 bits (1024 bytes); Max Bytes = 1024 − 66 = 958 bytes (958 characters for ASCII)

# Collect benchmark data into a DataFrame
df = collect_benchmark_data(key_sizes, message_sizes, num_samples=num_samples)

# Save the benchmark results to a CSV file for later analysis
df.to_csv("rsa_benchmark_results.csv", index=False)

# Plot line charts for different metrics
metrics = ["key_gen_time", "encryption_time", "decryption_time", "key_gen_memory", "ciphertext_size", "serialization_time"]
titles = [
    "Key Generation Time",
    "Encryption Time",
    "Decryption Time",
    "Key Generation Memory",
    "Ciphertext Size",
    "Serialization Time",
]

# Generate plots for each metric
for metric, title in zip(metrics, titles):
    plot_line_charts(df, key_sizes, message_sizes, metric, title)
    plot_heatmaps(df, key_sizes, message_sizes, metric, title)
