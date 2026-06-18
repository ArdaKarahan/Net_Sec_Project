import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Set a clean, professional plotting style
sns.set_theme(style="whitegrid")
plt.rcParams.update({
    "font.size": 12,
    "axes.labelsize": 14,
    "axes.titlesize": 16,
    "xtick.labelsize": 11,
    "ytick.labelsize": 11,
    "figure.titlesize": 18
})

def load_and_clean_csv(file_path):
    """Loads a metrics CSV and gracefully handles malformed duplicate header rows."""
    if not os.path.exists(file_path):
        print(f"⚠️ Warning: {file_path} not found. Skipping.")
        return None
    
    # Read the file line by line to filter out mid-stream duplicate header text lines
    clean_lines = []
    with open(file_path, "r") as f:
        header = f.readline().strip()
        clean_lines.append(header)
        for line in f:
            line_str = line.strip()
            # Skip rows that are empty or replicate the header string mid-file
            if not line_str or "timestamp" in line_str.lower():
                continue
            clean_lines.append(line_str)
            
    # Parse the clean lines into a DataFrame
    from io import StringIO
    df = pd.read_csv(StringIO("\n".join(clean_lines)))
    
    # Convert timestamps to numeric elapsed time seconds for uniform plotting curves
    df['Elapsed_Seconds'] = range(len(df))
    return df

# ---------------------------------------------------------------------------
# 1. Load Datasets
# ---------------------------------------------------------------------------
data_map = {
    "Traditional (Classical)": "metrics_traditional.csv",
    "PQC Dilithium": "metrics_dilithium.csv",
    "PQC Falcon": "metrics_falcon.csv"
}

dfs = {}
for mode_name, file_name in data_map.items():
    cleaned_df = load_and_clean_csv(file_name)
    if cleaned_df is not None:
        dfs[mode_name] = cleaned_df

if not dfs:
    print("❌ Error: No valid metric CSV files found to plot. Make sure files are named correctly.")
    exit(1)

# ---------------------------------------------------------------------------
# 2. Generate Figure 1: CPU & Memory Overhead Profile
# ---------------------------------------------------------------------------
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
fig.suptitle("Computational Resource Saturation Comparison", weight="bold", y=0.98)

colors = {"Traditional (Classical)": "#2ecc71", "PQC Dilithium": "#e74c3c", "PQC Falcon": "#3498db"}

for mode_name, df in dfs.items():
    # Apply a gentle rolling average to smooth out background Docker host engine jitter
    smooth_cpu = df["cpu_percent"].rolling(window=3, min_periods=1).mean()
    ax1.plot(df["Elapsed_Seconds"], smooth_cpu, label=mode_name, color=colors[mode_name], linewidth=2.5)
    ax2.plot(df["Elapsed_Seconds"], df["memory_mb"], label=mode_name, color=colors[mode_name], linewidth=2.5)

ax1.set_title("CPU Utilization Profiles")
ax1.set_xlabel("Elapsed Time (Seconds)")
ax1.set_ylabel("CPU Utilization (%)")
ax1.set_ylim(0, 105)
ax1.legend(loc="upper right")

ax2.set_title("Process Memory Footprint Trends")
ax2.set_xlabel("Elapsed Time (Seconds)")
ax2.set_ylabel("System Memory Allocation (MB)")
ax2.legend(loc="upper left")

plt.tight_layout()
plt.savefig("pqc_computational_overhead.png", dpi=300)
print("💾 Saved resource profile: pqc_computational_overhead.png")

# ---------------------------------------------------------------------------
# 3. Generate Figure 2: Network Bandwidth Scaling Curve
# ---------------------------------------------------------------------------
plt.figure(figsize=(10, 6))
plt.title("Network Throughput Constraints under Bounded Queues", weight="bold", pad=15)

for mode_name, df in dfs.items():
    # Convert absolute bytes to Megabytes per second for immediate clarity
    mb_sent = df["net_bytes_sent"] / (1024 * 1024)
    smooth_net = mb_sent.rolling(window=3, min_periods=1).mean()
    plt.plot(df["Elapsed_Seconds"], smooth_net, label=mode_name, color=colors[mode_name], linewidth=2.5)

plt.xlabel("Elapsed Time (Seconds)")
plt.ylabel("Data Transmitted (MB / Sec)")
plt.yscale("linear")  # Change to "log" if PQC data variance spans multiple orders of magnitude
plt.legend(loc="upper right")

plt.tight_layout()
plt.savefig("pqc_network_bandwidth.png", dpi=300)
print("💾 Saved network profile: pqc_network_bandwidth.png")
print("\n🎉 All visualizations generated successfully!")