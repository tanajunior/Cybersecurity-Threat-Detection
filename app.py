# app.py - Flask Backend for Anomaly Prediction

import os
from flask import Flask, request, jsonify
from flask_cors import CORS # Required for cross-origin requests from frontend
import torch
import torch.nn as nn
import pandas as pd
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
import numpy as np
import pickle

# --- 1. Initialize Flask App ---
app = Flask(__name__)
CORS(app) # Enable CORS for all routes, allowing frontend to connect

# --- 2. Configuration for Model and Preprocessor Loading ---
MODEL_SAVE_PATH = 'anomaly_detection_model.pth'
SCALER_LOAD_PATH = 'minmax_scaler.pkl'
LABEL_ENCODERS_LOAD_PATH = 'label_encoders.pkl'

# --- Define the Transformer Model Architecture (must match train_model.py) ---
class TrafficAnomalyTransformer(nn.Module):
    def __init__(self, input_dim, d_model, nhead, num_encoder_layers, dim_feedforward, dropout=0.0):
        super(TrafficAnomalyTransformer, self).__init__()
        self.embedding_layer = nn.Linear(input_dim, d_model)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=dim_feedforward,
            dropout=dropout,
            batch_first=True
        )
        self.transformer_encoder = nn.TransformerEncoder(encoder_layer, num_encoder_layers)
        self.output_layer = nn.Linear(d_model, 1)

    def forward(self, src):
        src = self.embedding_layer(src)
        transformer_output = self.transformer_encoder(src)
        pooled_output = torch.mean(transformer_output, dim=1)
        output = self.output_layer(pooled_output)
        return output

# --- 3. Global Variables for Loaded Model and Preprocessing Tools ---
GLOBAL_INPUT_FEATURES_ORDER = None
GLOBAL_SCALER = None
GLOBAL_LABEL_ENCODERS = {}
model = None # Initialize model to None, will be loaded on startup

# --- Function to load model and preprocessors on app startup ---
def load_artifacts():
    global GLOBAL_INPUT_FEATURES_ORDER, GLOBAL_SCALER, GLOBAL_LABEL_ENCODERS, model
    
    try:
        # Determine INPUT_DIM and feature order from processed_network_traffic.csv
        # This ensures the Flask app uses the exact same feature order as the trained model
        if os.path.exists('processed_network_traffic.csv'):
            temp_df_for_cols = pd.read_csv('processed_network_traffic.csv', nrows=1)
            # Exclude target and flow_id from features used by the model
            GLOBAL_INPUT_FEATURES_ORDER = [col for col in temp_df_for_cols.columns if col not in ['label_binary', 'flow_id', 'label']]
            INPUT_DIM = len(GLOBAL_INPUT_FEATURES_ORDER)
            app.logger.info(f"Determined INPUT_DIM from processed_network_traffic.csv: {INPUT_DIM}")
            app.logger.info(f"Expected feature order (first 5): {GLOBAL_INPUT_FEATURES_ORDER[:5]}...")
        else:
            app.logger.error("ERROR: 'processed_network_traffic.csv' not found. Cannot determine GLOBAL_INPUT_FEATURES_ORDER. Using default INPUT_DIM (79). This may lead to prediction errors.")
            # Fallback if the processed data is missing. This is a critical warning.
            INPUT_DIM = 79 # A common default for this dataset
            GLOBAL_INPUT_FEATURES_ORDER = [f'feature_{i}' for i in range(INPUT_DIM)]


        # Load the saved MinMaxScaler
        with open(SCALER_LOAD_PATH, 'rb') as f:
            GLOBAL_SCALER = pickle.load(f)
        app.logger.info(f"MinMaxScaler loaded successfully from {SCALER_LOAD_PATH}")
        if hasattr(GLOBAL_SCALER, 'data_min_') and hasattr(GLOBAL_SCALER, 'data_max_') and hasattr(GLOBAL_SCALER, 'feature_names_in_'):
            app.logger.info(f"Scaler data_min_ (first 10 features): {GLOBAL_SCALER.data_min_[:10]}")
            app.logger.info(f"Scaler data_max_ (first 10 features): {GLOBAL_SCALER.data_max_[:10]}")
            # Diagnostic check for specific important features
            try:
                if 'flow_bytes_s' in GLOBAL_SCALER.feature_names_in_:
                    fb_idx = list(GLOBAL_SCALER.feature_names_in_).index('flow_bytes_s')
                    app.logger.info(f"Scaler data_max_ for 'flow_bytes_s': {GLOBAL_SCALER.data_max_[fb_idx]}")
                if 'flow_packets_s' in GLOBAL_SCALER.feature_names_in_:
                    fp_idx = list(GLOBAL_SCALER.feature_names_in_).index('flow_packets_s')
                    app.logger.info(f"Scaler data_max_ for 'flow_packets_s': {GLOBAL_SCALER.data_max_[fp_idx]}")
            except ValueError:
                app.logger.warning("Could not find 'flow_bytes_s' or 'flow_packets_s' in scaler's feature names (this might be an issue).")
        else:
            app.logger.warning("WARNING: Loaded scaler does not have 'data_min_', 'data_max_' or 'feature_names_in_'. This may cause prediction issues.")

        # Load the saved LabelEncoders
        with open(LABEL_ENCODERS_LOAD_PATH, 'rb') as f:
            GLOBAL_LABEL_ENCODERS = pickle.load(f)
        app.logger.info(f"LabelEncoders loaded successfully from {LABEL_ENCODERS_LOAD_PATH}")

        # Initialize and load the PyTorch model
        if os.path.exists(MODEL_SAVE_PATH):
            model = TrafficAnomalyTransformer(
                input_dim=INPUT_DIM, # Use the determined INPUT_DIM
                d_model=64,
                nhead=1,
                num_encoder_layers=1,
                dim_feedforward=128,
                dropout=0.0
            )
            # Load the state dictionary to the model, mapping to CPU
            model.load_state_dict(torch.load(MODEL_SAVE_PATH, map_location=torch.device('cpu')))
            model.eval() # Set model to evaluation mode (important for inference)
            app.logger.info(f"Model loaded successfully from {MODEL_SAVE_PATH} with input_dim={INPUT_DIM}")
        else:
            app.logger.error(f"ERROR: Model file not found at {MODEL_SAVE_PATH}. Please ensure train_model.py ran successfully to create it.")
            model = None # Set model to None if file not found, so /predict endpoint returns 503

    except Exception as e:
        app.logger.critical(f"CRITICAL ERROR during model/preprocessor loading: {e}")
        # Reset all globals to None/empty if any part of loading fails
        model = None
        GLOBAL_INPUT_FEATURES_ORDER = None
        GLOBAL_SCALER = None
        GLOBAL_LABEL_ENCODERS = {}

# Call load_artifacts when the Flask app starts up
# This ensures model and preprocessors are ready before any requests come in
with app.app_context():
    load_artifacts()


# --- 4. Preprocessing Function for a Single Flow ---
def preprocess_single_flow(raw_flow_data):
    """
    Preprocesses a single raw network flow (dictionary) for model inference.
    Assumes raw_flow_data keys match original CSV column names (after cleaning).
    Uses the globally loaded scaler and encoders.
    """
    if model is None or GLOBAL_SCALER is None or GLOBAL_INPUT_FEATURES_ORDER is None:
        raise ValueError("Model or preprocessing tools not fully loaded on server startup. Please check server logs.")

    single_df = pd.DataFrame([raw_flow_data])
    
    # Standardize column names (must match preprocess_data.py)
    single_df.columns = single_df.columns.str.strip().str.lower()
    single_df.columns = single_df.columns.str.replace(' ', '_').str.replace('/', '_').str.replace('.', '', regex=False).str.replace('__', '_')

    # Reindex the input DataFrame to match the expected feature order from training
    # This step is CRITICAL to ensure features are in the correct position for the model
    # fill_value=0 or median/mean for missing features, depends on data. For simplicity here, 0.
    temp_df_for_processing = single_df.reindex(columns=GLOBAL_INPUT_FEATURES_ORDER, fill_value=0)

    # Handle infinity values, NaNs, and ensure correct data types for processing
    temp_df_for_processing.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    for col in temp_df_for_processing.columns:
        if col in GLOBAL_LABEL_ENCODERS: # If it's a known categorical column based on saved encoders
            temp_df_for_processing[col] = temp_df_for_processing[col].fillna('Unknown_Category_Placeholder').astype(str)
        else: # Otherwise, assume numerical
            temp_df_for_processing[col] = pd.to_numeric(temp_df_for_processing[col], errors='coerce')
            temp_df_for_processing[col].fillna(0, inplace=True) # Fill numerical NaNs with 0

    # Apply feature engineering (packets_per_flow_duration)
    # Ensure columns exist before attempting calculation
    if 'total_fwd_packets' in temp_df_for_processing.columns and \
       'total_backward_packets' in temp_df_for_processing.columns and \
       'flow_duration' in temp_df_for_processing.columns:
        
        temp_df_for_processing['packets_per_flow_duration'] = \
            (temp_df_for_processing['total_fwd_packets'] + temp_df_for_processing['total_backward_packets']) / \
            (temp_df_for_processing['flow_duration'] + 1e-6) # Add epsilon to avoid division by zero

        temp_df_for_processing['packets_per_flow_duration'].replace([np.inf, -np.inf], 0, inplace=True)
        temp_df_for_processing['packets_per_flow_duration'].fillna(0, inplace=True)
        temp_df_for_processing['packets_per_flow_duration'] = temp_df_for_processing['packets_per_flow_duration'].astype(float)
    else:
        # If necessary columns for feature engineering are missing, ensure the feature is still present with a default
        if 'packets_per_flow_duration' not in temp_df_for_processing.columns:
             temp_df_for_processing['packets_per_flow_duration'] = 0.0


    # Apply categorical encoding using the loaded label encoders
    # Iterate through GLOBAL_INPUT_FEATURES_ORDER to ensure consistency
    for col in GLOBAL_INPUT_FEATURES_ORDER:
        if col in GLOBAL_LABEL_ENCODERS: # Only process if it's a known categorical feature
            val = str(temp_df_for_processing[col].iloc[0])
            le = GLOBAL_LABEL_ENCODERS[col]
            # Handle unseen categories gracefully: if value is not in known classes, map to a default (e.g., first class or 0)
            if val not in le.classes_:
                if 'Unknown_Category_Placeholder' in le.classes_:
                    temp_df_for_processing[col] = le.transform(['Unknown_Category_Placeholder'])[0]
                elif len(le.classes_) > 0: # Fallback to the first class if 'Unknown' isn't a class
                    temp_df_for_processing[col] = le.transform([le.classes_[0]])[0]
                else: # Final fallback if encoder has no classes (highly unlikely if train_model ran)
                    temp_df_for_processing[col] = 0
            else:
                temp_df_for_processing[col] = le.transform([val])[0]
        # Ensure that non-categorical features (which are numerical) are still floats
        elif pd.api.types.is_numeric_dtype(temp_df_for_processing[col]):
            temp_df_for_processing[col] = temp_df_for_processing[col].astype(float)
        else:
            # If a column that was supposed to be numerical is still not numeric, default to 0.0
            temp_df_for_processing[col] = 0.0


    # Handle binary/flag features: clip values between 0 and 1
    # This prevents very large flag values from skewing scaling
    flag_columns = ['fin_flag_count', 'syn_flag_count', 'rst_flag_count', 'psh_flag_count', 
                    'ack_flag_count', 'urg_flag_count', 'cwe_flag_count', 'ece_flag_count',
                    'fwd_psh_flags', 'bwd_psh_flags', 'fwd_urg_flags', 'bwd_urg_flags']
    
    for flag_col in flag_columns:
        if flag_col in temp_df_for_processing.columns:
            temp_df_for_processing[flag_col] = temp_df_for_processing[flag_col].astype(float).clip(0, 1)


    # Apply numerical scaling using the loaded MinMaxScaler
    # Use scaler.feature_names_in_ to get the exact columns the scaler was fitted on
    # This is safer than relying on `numerical_cols` which might be derived differently
    numerical_cols_to_scale_by_scaler = list(GLOBAL_SCALER.feature_names_in_) if hasattr(GLOBAL_SCALER, 'feature_names_in_') else []

    # Ensure all columns in numerical_cols_to_scale_by_scaler are float type before scaling
    for col in numerical_cols_to_scale_by_scaler:
        if col in temp_df_for_processing.columns:
            temp_df_for_processing[col] = pd.to_numeric(temp_df_for_processing[col], errors='coerce').fillna(0).astype(float)

    if numerical_cols_to_scale_by_scaler and GLOBAL_SCALER:
        # Create a DataFrame slice with only the columns the scaler expects
        data_to_scale_df = temp_df_for_processing[numerical_cols_to_scale_by_scaler]
        
        # Transform the numerical data using the global scaler
        scaled_values_np = GLOBAL_SCALER.transform(data_to_scale_df)
        
        # Put the scaled values back into the DataFrame
        temp_df_for_processing[numerical_cols_to_scale_by_scaler] = scaled_values_np
    else:
        app.logger.warning("WARNING: Skipping numerical scaling. Check scaler loading or numerical_cols_to_scale_by_scaler.")


    # Final step: Ensure the DataFrame has the exact column order as GLOBAL_INPUT_FEATURES_ORDER
    # This is absolutely critical for the PyTorch model's input
    final_features_df = temp_df_for_processing[GLOBAL_INPUT_FEATURES_ORDER]
    
    # Convert the processed DataFrame to a PyTorch tensor
    # Unsqueeze(1) adds a sequence length dimension of 1, as expected by the Transformer
    processed_tensor = torch.tensor(final_features_df.values, dtype=torch.float32).unsqueeze(1)
    
    return processed_tensor

# --- 5. Define API Endpoint for Predictions ---
@app.route('/predict', methods=['POST'])
def predict():
    # If model or preprocessors failed to load on startup, return 503 Service Unavailable
    if model is None or GLOBAL_SCALER is None or GLOBAL_INPUT_FEATURES_ORDER is None:
        return jsonify({"error": "Server is not ready. Model or preprocessing tools failed to load on startup. Please check server logs."}), 503

    try:
        raw_data = request.get_json(force=True) # Get JSON data from the request body
        if not raw_data:
            return jsonify({"error": "No JSON data provided in the request body."}), 400

        # Preprocess the incoming raw data using the globally loaded preprocessors
        processed_input = preprocess_single_flow(raw_data)
        
        # Move tensor to CPU for inference (model was also loaded to CPU)
        processed_input = processed_input.to(torch.device('cpu'))

        # Make prediction using the loaded model
        model.eval() # Ensure model is in evaluation mode for consistent results
        with torch.no_grad(): # Disable gradient calculations for faster inference
            output = model(processed_input)
            probability = torch.sigmoid(output).item() # Apply sigmoid to get probability between 0 and 1
            prediction_label = "Anomaly" if probability > 0.5 else "Benign" # Classify based on 0.5 threshold

        # --- TEMPORARY DEBUG OVERRIDE FOR FORCING ANOMALY ---
        # If total_fwd_packets is very high, force prediction to 'Anomaly'
        # This helps test the frontend's anomaly handling and and Firestore saving.
        # This MUST be removed for actual model evaluation.
        # This entire block will be removed or commented out.
        # if 'total_fwd_packets' in raw_data and raw_data['total_fwd_packets'] > 1000: # Using a high value from exampleAttackFlow
        #     prediction_label = 'Anomaly'
        #     probability = 0.999 # Assign a high probability
        #     app.logger.info(f"DEBUG: Forced Prediction Label: '{prediction_label}' (total_fwd_packets > 1000)")
        # --- END TEMPORARY DEBUG OVERRIDE ---


        # Print debug information to the console where Flask is running
        app.logger.info(f"\n--- BACKEND PREDICTION DEBUG ---")
        app.logger.info(f"Raw Input (first 5 keys): {dict(list(raw_data.items())[:5])}")
        app.logger.info(f"Calculated Probability: {probability:.4f}")
        app.logger.info(f"Assigned Prediction Label: '{prediction_label}'")
        app.logger.info(f"--- END BACKEND PREDICTION DEBUG ---\n")

        # Return the prediction result as JSON
        return jsonify({
            "prediction": prediction_label,
            "anomaly_probability": f"{probability:.4f}" # Format to 4 decimal places
        })

    except ValueError as ve:
        # Handle data-related value errors during preprocessing
        app.logger.error(f"Data processing error: {str(ve)}. Please check your input format.")
        return jsonify({"error": f"Data processing error: {str(ve)}. Please check your input format."}), 400
    except KeyError as ke:
        # Handle missing keys in the input data
        app.logger.error(f"Missing expected data key: {ke}. Please ensure all required network flow features are provided.")
        return jsonify({"error": f"Missing expected data key: {ke}. Please ensure all required network flow features are provided."}), 400
    except Exception as e:
        # Catch any other unexpected errors during prediction
        app.logger.critical(f"An unexpected error occurred during prediction: {e}")
        return jsonify({"error": "An internal server error occurred during prediction. Please check server logs."}), 500

# --- 6. Basic Health Check Endpoint ---
@app.route('/health', methods=['GET'])
def health_check():
    """
    Provides a simple health check endpoint to verify server status and model loading.
    """
    status = "healthy" if model is not None else "unhealthy - model not loaded"
    return jsonify({"status": status, "model_loaded": model is not None}), 200

# --- 7. Run the Flask App (for development only) ---
if __name__ == '__main__':
    # app.run(debug=True) enables debugger and auto-reloader (useful during development)
    # host='0.0.0.0' makes the server publicly accessible on your network (for testing from other devices)
    # port=5000 is the standard port for Flask
    app.run(debug=True, host='0.0.0.0', port=5000)
