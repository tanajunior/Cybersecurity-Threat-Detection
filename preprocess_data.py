# preprocess_data.py - Initial Data Preprocessing Script

import pandas as pd
from sklearn.preprocessing import LabelEncoder
import numpy as np
import os

# --- Configuration ---
# Path to the folder containing your raw CSV files
DATA_FOLDER = 'data'

# List of all your CICIDS2017 raw CSV files
CSV_FILES = [
    'Monday-WorkingHours.pcap_ISCX.csv',
    'Tuesday-WorkingHours.pcap_ISCX.csv',
    'Wednesday-WorkingHours.pcap_ISCX.csv',
    'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
    'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
    'Friday-WorkingHours-Morning.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
    'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'
]

# Name of the output processed CSV file
OUTPUT_PROCESSED_FILE = 'processed_network_traffic.csv'

# Sampling Configuration:
# Number of BENIGN samples to keep in the final processed dataset
NUM_BENIGN_SAMPLES = 25000
# Number of ATTACK samples to keep in the final processed dataset
# This is set high to ensure good representation of anomalies
NUM_ATTACK_SAMPLES = 200000

# --- Data Loading and Initial Cleaning Function ---
def load_and_clean_data(file_path):
    """
    Loads a single CSV file, cleans column names, and handles initial data issues.
    """
    try:
        # low_memory=False is crucial for large, mixed-type CSVs
        df = pd.read_csv(file_path, low_memory=False)
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        return pd.DataFrame() # Return empty DataFrame on error

    # Step 1: Clean Column Names
    # Strip whitespace, convert to lowercase, replace special characters with underscores
    df.columns = df.columns.str.strip().str.lower()
    df.columns = df.columns.str.replace(' ', '_').str.replace('/', '_').str.replace('.', '', regex=False).str.replace('__', '_')

    # Step 2: Drop Duplicate Rows (can happen due to network capture or dataset creation)
    df.drop_duplicates(inplace=True)

    # Step 3: Handle Infinity Values (common in network flow data, e.g., division by zero rates)
    # Replace infinite values with NaN first
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Step 4: Drop columns that are mostly NaN (more than 90% missing values)
    initial_cols = df.shape[1]
    df.dropna(axis=1, thresh=int(len(df) * 0.1), inplace=True) # Keep column if it has at least 10% non-NaN values
    if df.shape[1] < initial_cols:
        print(f"Dropped {initial_cols - df.shape[1]} columns with too many missing values in {os.path.basename(file_path)}")

    # Step 5: Fill remaining NaN values after column dropping
    # For numerical columns, fill with 0 (a reasonable default for network features like packet counts, durations)
    for col in df.select_dtypes(include=np.number).columns:
        if df[col].isnull().any():
            df[col].fillna(0, inplace=True)

    # For object/categorical columns, fill with a placeholder string 'Missing'
    for col in df.select_dtypes(include='object').columns:
        if df[col].isnull().any():
            df[col].fillna('Missing', inplace=True)

    return df

# --- Feature Engineering Function ---
def feature_engineer(df):
    """
    Applies feature engineering steps to the DataFrame.
    """
    # Create 'packets_per_flow_duration' feature
    # Sum of forward and backward packets divided by flow duration
    # Add a small epsilon (1e-6) to the denominator to prevent division by zero errors
    df['packets_per_flow_duration'] = (df['total_fwd_packets'] + df['total_backward_packets']) / (df['flow_duration'] + 1e-6)
    
    # Handle any inf/-inf values that might arise from edge cases (e.g., flow_duration was 0 even with epsilon)
    df['packets_per_flow_duration'].replace([np.inf, -np.inf], 0, inplace=True)
    df['packets_per_flow_duration'].fillna(0, inplace=True) # Fill any NaNs remaining (e.g., if sum of packets was NaN)

    print("Feature engineering complete: 'packets_per_flow_duration' created.")
    return df

# --- Main Preprocessing Logic ---
def main():
    all_data_frames = []
    print("Starting data loading and initial cleaning for all CSV files...")

    # Iterate through each CSV file, load, clean, and append to a list
    for file_name in CSV_FILES:
        file_path = os.path.join(DATA_FOLDER, file_name)
        if os.path.exists(file_path):
            df = load_and_clean_data(file_path)
            if not df.empty:
                all_data_frames.append(df)
            else:
                print(f"No data processed from: {file_name}")
        else:
            print(f"File not found: {file_path}. Please ensure all CSVs are in the '{DATA_FOLDER}' directory.")

    if not all_data_frames:
        print("No data frames were loaded. Please check your DATA_FOLDER and CSV_FILES list.")
        return

    # Concatenate all individual DataFrames into one large DataFrame
    combined_df = pd.concat(all_data_frames, ignore_index=True)
    print(f"\nAll raw data combined. Initial shape: {combined_df.shape}")

    # Drop columns that are known to be identifiers or consistently problematic across the full dataset
    # 'flow_id' is an identifier and not a useful feature for ML
    cols_to_drop_final = ['flow_id']
    combined_df.drop(columns=cols_to_drop_final, errors='ignore', inplace=True)
    print(f"Dropped identifier columns. Current shape: {combined_df.shape}")

    # Convert 'label' column to binary (0 for Benign, 1 for Attack)
    if 'label' in combined_df.columns:
        combined_df['label'] = combined_df['label'].str.strip().str.lower()
        # Create a new binary column 'label_binary'
        # Any label NOT 'benign' is considered an attack (1), 'benign' is 0
        combined_df['label_binary'] = combined_df['label'].apply(lambda x: 0 if x == 'benign' else 1)
        print("Binary label 'label_binary' created based on original 'label' column.")
    else:
        print("Warning: 'label' column not found in combined data. Cannot create 'label_binary'.")
        # If 'label' is missing, create a dummy 'label_binary' to prevent errors in later stages
        combined_df['label_binary'] = 0
        print("A dummy 'label_binary' column (all zeros) has been added.")


    # Separate data into benign and attack for controlled sampling
    benign_df = combined_df[combined_df['label_binary'] == 0]
    attack_df = combined_df[combined_df['label_binary'] == 1]

    print(f"\nOriginal Benign samples identified: {len(benign_df)}")
    print(f"Original Attack samples identified: {len(attack_df)}")

    # Apply sampling to create a more balanced dataset for training
    # Sample benign traffic down to NUM_BENIGN_SAMPLES
    if len(benign_df) > NUM_BENIGN_SAMPLES:
        benign_sampled = benign_df.sample(n=NUM_BENIGN_SAMPLES, random_state=42)
        print(f"Benign samples reduced to {len(benign_sampled)}.")
    else:
        benign_sampled = benign_df
        print(f"Warning: Not enough benign samples ({len(benign_df)}) to reach target ({NUM_BENIGN_SAMPLES}). Using all available.")

    # Sample attack traffic, ensuring we get a high number of anomaly examples
    if len(attack_df) > NUM_ATTACK_SAMPLES:
        attack_sampled = attack_df.sample(n=NUM_ATTACK_SAMPLES, random_state=42)
        print(f"Attack samples reduced to {len(attack_sampled)}.")
    else:
        attack_sampled = attack_df
        print(f"Warning: Not enough attack samples ({len(attack_df)}) to reach target ({NUM_ATTACK_SAMPLES}). Using all available.")

    # Concatenate the sampled benign and attack data, then shuffle the entire dataset
    sampled_df = pd.concat([benign_sampled, attack_sampled]).sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"Final sampled and balanced data shape: {sampled_df.shape}")

    # Apply Feature Engineering
    sampled_df = feature_engineer(sampled_df)

    # Convert all columns to numeric where possible, filling any new NaNs with 0
    # This step is critical before model training as PyTorch models expect numeric input
    for col in sampled_df.columns:
        if sampled_df[col].dtype == 'object':
            # Attempt to convert object columns to numeric if they contain numbers as strings
            sampled_df[col] = pd.to_numeric(sampled_df[col], errors='coerce')
        
        # Fill any NaNs that resulted from coercion or previous steps, specifically for numerical columns
        if sampled_df[col].isnull().any() and pd.api.types.is_numeric_dtype(sampled_df[col]):
            sampled_df[col].fillna(0, inplace=True)
        # If it's still an object column (i.e., truly categorical strings), handle with LabelEncoder below

    # Apply Label Encoding to remaining truly categorical (object) features
    # This step should happen AFTER numerical processing to avoid encoding numerical values by mistake
    categorical_cols_to_encode = sampled_df.select_dtypes(include='object').columns.tolist()
    # Exclude the original 'label' column if it still exists and we want to drop it later
    if 'label' in categorical_cols_to_encode:
        categorical_cols_to_encode.remove('label')

    # Note: Label encoders themselves will be saved in train_model.py, not here
    # This loop just performs the encoding for the processed CSV
    for col in categorical_cols_to_encode:
        le = LabelEncoder()
        sampled_df[col] = le.fit_transform(sampled_df[col].astype(str))
    
    print("Categorical features encoded (not saved here, but applied to data).")


    # Drop the original 'label' column as 'label_binary' is our target
    final_processed_df = sampled_df.drop(columns=['label'], errors='ignore')

    # Save the processed data to a CSV file
    output_path = os.path.join(os.getcwd(), OUTPUT_PROCESSED_FILE)
    final_processed_df.to_csv(output_path, index=False)
    print(f"\nProcessed and sampled data successfully saved to: {output_path}")
    print(f"Final processed data shape: {final_processed_df.shape}")
    print("Data preprocessing complete!")

if __name__ == '__main__':
    main()
