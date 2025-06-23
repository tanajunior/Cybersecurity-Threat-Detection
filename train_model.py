# train_model.py - Model Training Script (REVISED for 30 EPOCHS and robust saving)

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
import os
import pickle

# Important: Set number of threads for PyTorch to avoid potential issues on some systems (e.g., macOS)
torch.set_num_threads(1)

# --- Configuration ---
PROCESSED_DATA_FILE = 'processed_network_traffic.csv'
MODEL_SAVE_PATH = 'anomaly_detection_model.pth'
SCALER_SAVE_PATH = 'minmax_scaler.pkl'
LABEL_ENCODERS_SAVE_PATH = 'label_encoders.pkl'

BATCH_SIZE = 64
EPOCHS = 30 # Increased number of training epochs for better model learning
LEARNING_RATE = 0.001
TEST_SIZE = 0.2 # 20% of the data will be used for testing

# --- 1. Define the Transformer Model Architecture ---
class TrafficAnomalyTransformer(nn.Module):
    def __init__(self, input_dim, d_model, nhead, num_encoder_layers, dim_feedforward, dropout=0.0):
        super(TrafficAnomalyTransformer, self).__init__()
        # Embedding layer to project input features to d_model dimension
        self.embedding_layer = nn.Linear(input_dim, d_model)
        
        # Transformer Encoder Layer definition
        # batch_first=True means input tensors will be (batch_size, sequence_length, features)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead, # Number of attention heads (must divide d_model)
            dim_feedforward=dim_feedforward, # Dimension of the feedforward network model
            dropout=dropout,
            batch_first=True
        )
        # Stacking multiple encoder layers to form the Transformer Encoder
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_encoder_layers)
        
        # Output layer to produce a single anomaly score
        self.output_layer = nn.Linear(d_model, 1)

    def forward(self, src):
        # Apply embedding layer to the input source
        src = self.embedding_layer(src)
        # Pass through the Transformer Encoder
        transformer_output = self.transformer_encoder(src)
        # Global average pooling to reduce sequence dimension to a single feature vector
        pooled_output = torch.mean(transformer_output, dim=1)
        # Pass through the final output layer
        output = self.output_layer(pooled_output)
        return output

# --- 2. Data Preparation Function ---
def prepare_data(file_path):
    """
    Loads processed data, splits into train/test, scales numerical features,
    and converts to PyTorch DataLoaders. Saves scaler and label encoders.
    """
    print(f"Loading processed data from {file_path}...")
    df = pd.read_csv(file_path)
    print(f"Data loaded. Shape: {df.shape}")

    # Ensure 'label_binary' column exists for target variable
    if 'label_binary' not in df.columns:
        raise ValueError("The 'label_binary' column is missing. Please ensure preprocess_data.py ran successfully.")
    
    # Identify numerical and categorical columns from the processed DataFrame
    numerical_cols = df.select_dtypes(include=np.number).columns.tolist()
    # Remove the binary label from numerical features as it's the target
    numerical_cols = [col for col in numerical_cols if col != 'label_binary']

    categorical_cols = df.select_dtypes(include='object').columns.tolist()
    # If any original 'label' column survived, ensure it's not treated as a feature here
    if 'label' in categorical_cols:
        categorical_cols.remove('label')

    # Fit and save LabelEncoders for categorical features
    # These will be used later during inference in app.py
    current_label_encoders = {}
    for col in categorical_cols:
        le = LabelEncoder()
        # Fit on all unique values from the current dataframe to capture all classes
        le.fit(df[col].astype(str).unique())
        current_label_encoders[col] = le
        # Transform the column in the DataFrame
        df[col] = le.transform(df[col].astype(str))
    
    # Save the dictionary of fitted LabelEncoders
    with open(LABEL_ENCODERS_SAVE_PATH, 'wb') as f:
        pickle.dump(current_label_encoders, f)
    print(f"LabelEncoders saved to {LABEL_ENCODERS_SAVE_PATH}")

    # Define the final order of features to be used by the model
    # This order must be consistent between training and inference
    final_features_order = numerical_cols + categorical_cols
    # Ensure all selected features are actually present in the DataFrame
    final_features_order = [col for col in final_features_order if col in df.columns]

    X = df[final_features_order] # Features DataFrame
    y = df['label_binary'] # Target Series

    print(f"Features (X) shape: {X.shape}, Target (y) shape: {y.shape}")
    print(f"Selected features for model (first 5): {final_features_order[:5]}...")
    print(f"Total features: {len(final_features_order)}")

    # Convert to NumPy arrays for splitting (needed for sklearn's train_test_split)
    X_np = X.values
    y_np = y.values

    # Split data into training and testing sets
    # stratify=y ensures that the proportion of benign/attack samples is maintained in both train and test sets
    X_train, X_test, y_train, y_test = train_test_split(X_np, y_np, test_size=TEST_SIZE, random_state=42, stratify=y)
    print(f"Train shapes: X={X_train.shape}, y={y_train.shape}")
    print(f"Test shapes: X={X_test.shape}, y={y_test.shape}")

    # --- Scaling Numerical Features using MinMaxScaler ---
    print("Fitting MinMaxScaler on numerical features of training data...")
    scaler = MinMaxScaler()
    
    # Create DataFrames from NumPy arrays to apply scaling selectively to numerical columns
    X_train_df_for_scaling = pd.DataFrame(X_train, columns=final_features_order)
    X_test_df_for_scaling = pd.DataFrame(X_test, columns=final_features_order)

    # Fit the scaler ONLY on the numerical features of the training data
    # This step calculates min/max for each numerical feature from training data
    scaler.fit(X_train_df_for_scaling[numerical_cols])
    
    # Save the fitted scaler immediately after fitting
    with open(SCALER_SAVE_PATH, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"MinMaxScaler saved to {SCALER_SAVE_PATH}")
    
    # Print details of the fitted scaler for verification
    if hasattr(scaler, 'data_min_') and hasattr(scaler, 'data_max_') and hasattr(scaler, 'feature_names_in_'):
        print(f"Scaler data_min_ (first 10 features): {scaler.data_min_[:10]}")
        print(f"Scaler data_max_ (first 10 features): {scaler.data_max_[:10]}")
        # Specific checks for 'flow_bytes_s' and 'flow_packets_s'
        try:
            if 'flow_bytes_s' in scaler.feature_names_in_:
                fb_idx = list(scaler.feature_names_in_).index('flow_bytes_s')
                print(f"Scaler data_max_ for 'flow_bytes_s': {scaler.data_max_[fb_idx]}")
            if 'flow_packets_s' in scaler.feature_names_in_:
                fp_idx = list(scaler.feature_names_in_).index('flow_packets_s')
                print(f"Scaler data_max_ for 'flow_packets_s': {scaler.data_max_[fp_idx]}")
        except ValueError:
            print("Could not find 'flow_bytes_s' or 'flow_packets_s' in scaler's feature names (this might be an issue).")
    else:
        print("WARNING: Loaded scaler does not have 'data_min_', 'data_max_' or 'feature_names_in_'. This may cause issues.")


    # Transform both training and testing numerical data using the fitted scaler
    X_train_df_for_scaling[numerical_cols] = scaler.transform(X_train_df_for_scaling[numerical_cols])
    X_test_df_for_scaling[numerical_cols] = scaler.transform(X_test_df_for_scaling[numerical_cols])

    # Reconstruct the NumPy arrays from the scaled DataFrames
    X_train_scaled = X_train_df_for_scaling.values
    X_test_scaled = X_test_df_for_scaling.values

    # Convert NumPy arrays to PyTorch tensors
    # Unsqueeze(1) adds a dimension of size 1 at index 1 for the sequence length (Transformer expects sequence input)
    X_train_tensor = torch.tensor(X_train_scaled, dtype=torch.float32).unsqueeze(1)
    y_train_tensor = torch.tensor(y_train, dtype=torch.float32).unsqueeze(1)
    X_test_tensor = torch.tensor(X_test_scaled, dtype=torch.float32).unsqueeze(1)
    y_test_tensor = torch.tensor(y_test, dtype=torch.float32).unsqueeze(1)

    # Create TensorDatasets and DataLoaders for efficient batch processing during training
    train_dataset = TensorDataset(X_train_tensor, y_train_tensor)
    test_dataset = TensorDataset(X_test_tensor, y_test_tensor)

    train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=BATCH_SIZE, shuffle=False)

    # Return loaders, the input dimension for the model, and true test labels for evaluation
    return train_loader, test_loader, len(final_features_order), y_test_tensor, final_features_order

# --- 3. Training Function ---
def train_model(model, train_loader, criterion, optimizer, device):
    """
    Performs one epoch of training.
    """
    model.train() # Set model to training mode
    total_loss = 0
    for batch_idx, (data, target) in enumerate(train_loader):
        data, target = data.to(device), target.to(device) # Move data to appropriate device (CPU/GPU)
        optimizer.zero_grad() # Clear gradients from previous step
        output = model(data) # Forward pass
        loss = criterion(output, target) # Calculate loss
        loss.backward() # Backpropagation
        optimizer.step() # Update model parameters
        total_loss += loss.item() # Accumulate loss
    avg_loss = total_loss / len(train_loader)
    print(f"Train Epoch Loss: {avg_loss:.4f}")
    return avg_loss

# --- 4. Evaluation Function ---
def evaluate_model(model, test_loader, criterion, device, y_true_labels):
    """
    Evaluates the model on the test set and prints performance metrics.
    """
    model.eval() # Set model to evaluation mode
    total_loss = 0
    predictions = []
    with torch.no_grad(): # Disable gradient calculation for inference
        for data, target in test_loader:
            data, target = data.to(device), target.to(device)
            output = model(data)
            total_loss += criterion(output, target).item() # Accumulate loss
            # Apply sigmoid and threshold at 0.5 to get binary predictions
            predicted = (torch.sigmoid(output) > 0.5).int()
            predictions.append(predicted.cpu().numpy()) # Store predictions

    avg_loss = total_loss / len(test_loader)
    print(f"Test Loss: {avg_loss:.4f}")

    y_pred = np.concatenate(predictions).flatten() # Flatten predictions for metric calculation
    y_true = y_true_labels.cpu().numpy().flatten() # Flatten true labels for metric calculation

    # Print evaluation metrics
    print("\nEvaluation Metrics:")
    # Add zero_division=0 to handle cases where a class might have no true or predicted samples
    print(f"Accuracy : {accuracy_score(y_true, y_pred):.4f}")
    print(f"Precision: {precision_score(y_true, y_pred, zero_division=0):.4f}")
    print(f"Recall   : {recall_score(y_true, y_pred, zero_division=0):.4f}")
    print(f"F1 Score : {f1_score(y_true, y_pred, zero_division=0):.4f}")

# --- 5. Main Execution Block ---
def main():
    # Determine the device (CPU or GPU if available)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")
    
    # Prepare data: load, split, scale, and create DataLoaders
    train_loader, test_loader, input_dim, y_test_labels, final_features_order = prepare_data(PROCESSED_DATA_FILE)

    # Initialize the Transformer model
    model = TrafficAnomalyTransformer(
        input_dim=input_dim,
        d_model=64, # Dimension of model (embedding size for Transformer)
        nhead=1, # Number of attention heads
        num_encoder_layers=1, # Number of Transformer Encoder layers
        dim_feedforward=128, # Dimension of the feedforward network
        dropout=0.0 # Dropout rate
    ).to(device) # Move model to selected device

    # Perform a dummy forward pass to catch potential initialization errors early
    try:
        with torch.no_grad():
            # Create a dummy input tensor with batch_size=1, sequence_length=1, input_dim
            dummy_input = torch.randn(1, 1, input_dim).to(device)
            _ = model(dummy_input)
            print("✅ Model forward pass test successful.")
    except Exception as e:
        print(f"❌ Model forward pass test failed: {e}")
        return # Exit if the model cannot even process a dummy input

    # Define loss function (Binary Cross-Entropy with Logits for sigmoid output)
    criterion = nn.BCEWithLogitsLoss()
    # Define optimizer (Adam is a good general-purpose optimizer)
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)

    print("\nStarting model training...")
    # Training loop
    for epoch in range(1, EPOCHS + 1):
        print(f"\n--- Epoch {epoch}/{EPOCHS} ---")
        train_loss = train_model(model, train_loader, criterion, optimizer, device)
        
    print("\nTraining complete. Evaluating model performance...")
    # Evaluate the trained model on the test set
    evaluate_model(model, test_loader, criterion, device, y_test_labels)

    # Save the trained model's state dictionary
    torch.save(model.state_dict(), MODEL_SAVE_PATH)
    print(f"\nModel saved to: {MODEL_SAVE_PATH}")
    print("Model training script finished.")

if __name__ == '__main__':
    main()
