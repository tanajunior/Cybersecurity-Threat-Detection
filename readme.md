Cybersecurity Threat Detection Dashboard
This project implements an AI-enhanced Cybersecurity Threat Detection Dashboard designed to monitor network traffic in real-time, detect anomalies using a trained machine learning model, and visualize potential threats. The system comprises a Python Flask backend that serves a deep learning model (Transformer-based) for anomaly prediction and a React frontend that provides an interactive dashboard for real-time monitoring and manual threat analysis.

The system is built to provide early warnings of unusual network behavior, helping administrators identify and respond to potential cyberattacks.

🌟 Project Overview
This project is an end-to-end system that covers:

Data Preprocessing Pipeline: Cleans, engineers features, and samples raw network traffic data (CICIDS2017) to prepare it for model training.

Transformer-based Anomaly Detection Model: A PyTorch deep learning model trained to classify network flows as 'Benign' or 'Anomaly'.

Flask REST API Backend: Serves the trained machine learning model, exposing a /predict endpoint for real-time anomaly detection of network flow data. It loads and utilizes saved data scalers and label encoders for consistent preprocessing during inference.

React Real-time Dashboard Frontend: A visually appealing and responsive user interface that automatically polls the backend for predictions, displays dynamic charts for network traffic and threat types, presents live alerts, and includes a notification system for critical detections. It also allows for manual prediction input.

Firebase Integration: Utilizes Firebase Authentication for anonymous user sessions and Firestore for persistent storage of detected anomaly alerts.

The overall system provides a proactive approach to identifying potential network anomalies, ensuring data persistence for analysis, and offering an intuitive monitoring interface.

🏗️ Architecture
The project's architecture is divided into three main components:

Machine Learning Core (Python/PyTorch):

Data Preprocessing (preprocess_data.py): Handles raw network flow data (CICIDS2017), performs essential cleaning (NaNs, infinities), feature engineering (e.g., packets_per_flow_duration), normalizes numerical features (MinMaxScaler), and encodes categorical features (LabelEncoder). Saves preprocessed data (processed_network_traffic.csv) and preprocessing artifacts (scaler.pkl, label_encoders.pkl) for consistent inference.

Model Training (train_model.py): Defines, trains, and evaluates a Transformer-based neural network for binary classification (Benign/Anomaly). Saves the trained model's weights (anomaly_detection_model.pth).

Backend API (Flask):

Python Flask Application (app.py): Loads the trained ML model and preprocessing artifacts at application startup. It exposes a /predict REST API endpoint that receives raw network flow data (JSON), preprocesses it using the loaded tools, and returns anomaly predictions.

Containerization (Dockerfile): Packages the Flask application and its Python dependencies into a Docker image for deployment.

Deployment: The Docker image is deployed as a serverless container on Google Cloud Run, providing a scalable and highly available prediction service.

Frontend Dashboard (React.js):

React Application: A single-page application built with React.js, featuring a dashboard layout with dynamic charts (Chart.js) for network traffic and threat types, and a table for recent alerts.

Firebase Integration: Utilizes Firebase SDK for:

Authentication: Anonymous user sign-in to secure access to Firestore.

Firestore: Real-time listeners to fetch historical alerts and functionality to save new alerts detected by the backend.

Backend Communication: Makes periodic fetch requests to the deployed Flask API for new anomaly predictions.

Deployment: The React application is built into static assets and deployed on Firebase Hosting.

💻 Technologies Used
Backend (Python):

Flask: Web framework for building the API.

PyTorch: Deep learning framework for the Transformer model.

Pandas: Data manipulation and analysis.

Scikit-learn: Data preprocessing (MinMaxScaler, LabelEncoder).

Flask-CORS: Handling Cross-Origin Resource Sharing for frontend communication.

Pickle: For serializing/deserializing Python objects (model, scalers, encoders).

Frontend (JavaScript/React):

React: JavaScript library for building user interfaces.

Vite: Fast build tool for modern web projects.

Chart.js / React Chart.js 2: For dynamic and interactive data visualizations.

Tailwind CSS: Utility-first CSS framework for styling.

Firebase (Auth, Firestore): For user authentication and persistent data storage.

📁 Project Structure
cybersecurity_project/
├── data/
│   ├── Monday-WorkingHours.pcap_ISCX.csv
│   ├── Tuesday-WorkingHours.pcap_ISCX.csv
│   └── ... (other CICIDS2017 CSV files - raw dataset)
├── frontend/
│   ├── public/             # Static assets for React
│   ├── src/
│   │   ├── App.jsx           # Main React dashboard component
│   │   ├── index.css
│   │   └── main.jsx
│   ├── index.html
│   ├── package.json        # Frontend dependencies and scripts
│   ├── vite.config.js      # Vite build configuration
│   └── build/              # Output directory for React production build (generated)
├── anomaly_detection_model.pth # Trained PyTorch model (generated)
├── minmax_scaler.pkl         # Fitted MinMaxScaler for numerical features (generated)
├── label_encoders.pkl        # Fitted LabelEncoders for categorical features (generated)
├── processed_network_traffic.csv # Cleaned and sampled data for training (generated)
├── preprocess_data.py        # Script for data cleaning and preparation
├── train_model.py            # Script for training the AI model
├── app.py                    # Flask backend API for serving predictions
├── Dockerfile                # Docker configuration for backend
├── requirements.txt          # Python dependencies for backend
└── firebase.json             # Firebase Hosting configuration
└── .dockerignore             # Files to ignore during Docker build

🛠️ Setup and Running Instructions (Local Development)
Follow these steps precisely to set up and run the entire project on your local machine.

Prerequisites
Python 3.8+: Installed on your system.

Node.js & npm: Installed on your system (Node.js 14+ recommended).

Git (Optional): For cloning the repository if you were to manage it via Git.

Internet Connection: Required for downloading datasets and npm packages.

Step 1: Project Initialization & Raw Data Acquisition
Create Project Directory:

mkdir cybersecurity_project
cd cybersecurity_project

Create Data Directory:

mkdir data

Download CICIDS2017 Dataset:

Go to: https://www.unb.ca/cic/datasets/ids-2017.html

Download all eight .pcap_ISCX.csv files listed under "Individual Days CSV Files".

Place all downloaded CSV files directly into the cybersecurity_project/data directory. Do not rename them.

Step 2: Data Preprocessing (Python)
Create preprocess_data.py:

In the cybersecurity_project directory, create a file named preprocess_data.py.

Paste the content of the preprocess_data.py script (as provided in our chat history) into this file.

Run Preprocessing Script:

Open a new terminal window.

Navigate to your cybersecurity_project directory:

cd cybersecurity_project

Run the script:

python preprocess_data.py

Wait for it to complete. It will print messages about loading data, cleaning, and finally "Processed and sampled data successfully saved to: processed_network_traffic.csv".

This step will also generate minmax_scaler.pkl and label_encoders.pkl.

Step 3: Model Training (Python)
Create train_model.py:

In the cybersecurity_project directory, create a file named train_model.py.

Paste the content of the train_model.py script (as provided in our chat history) into this file.

Run Model Training Script:

Open a new terminal window.

Navigate to your cybersecurity_project directory:

cd cybersecurity_project

Run the script:

python train_model.py

This step will take a significant amount of time (approx. 10-20 minutes or more depending on your system, due to 30 epochs and data size). Do NOT interrupt it.

Verify completion: It will print messages about each epoch's training loss, then evaluation metrics, and finally: "Model saved to: anomaly_detection_model.pth".

Step 4: Flask Backend Setup (Python)
Install Flask-CORS:

In a terminal, ensure you are in the cybersecurity_project directory:

cd cybersecurity_project

Install the necessary Python package:

pip install flask-cors  # or pip3 install flask-cors

Create app.py:

In the cybersecurity_project directory, create a file named app.py.

Paste the content of the app.py script (the latest version provided, with the anomaly override removed) into this file.

Run Flask Backend Locally:

Open a new terminal window.

Navigate to your cybersecurity_project directory:

cd cybersecurity_project

Run the server:

python app.py

Verify successful startup: It must print messages about loading the scaler, encoders, and model, and finally: * Running on http://127.0.0.1:5000.

Keep this terminal window open and running.

Step 5: React Frontend Setup (JavaScript/React)
Initialize React Project with Vite:

Open a new terminal window.

Navigate to your cybersecurity_project directory:

cd cybersecurity_project

Run the Vite command to create the frontend structure:

npm create vite@latest frontend -- --template react

Follow the prompts: press Enter for project name frontend, select React, then JavaScript + SWC.

Navigate to Frontend Directory & Install Dependencies:

cd frontend
npm install
# Install specific Chart.js and Firebase dependencies
npm install chart.js react-chartjs-2 firebase

Place App.jsx Code:

Navigate to cybersecurity_project/frontend/src/.

Open App.jsx in your text editor.

Replace its entire content with the latest App.jsx code provided in our chat history (the version with the enhanced Firestore listener readiness and duplicate app check). Save the file.

Create/Update vite.config.js:

In your frontend/ directory, ensure vite.config.js is configured for relative paths and build output:

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: './', // CRITICAL: Ensures relative paths for assets in the build
  build: {
    outDir: 'build', // Output to 'build' directory
    assetsDir: 'static', // Assets like JS/CSS go into a 'static' subfolder
  }
})

Run React Frontend Locally:

In the cybersecurity_project/frontend terminal (or a new one, making sure you cd into frontend first):

npm run dev

Verify successful startup: It will print VITE vX.Y.Z ready in ... ms and ➜ Local: http://localhost:5173/.

Keep this terminal window open and running.

6. How to Use the Dashboard (Local)
Open your browser and navigate to http://localhost:5173/.

Observe Real-time Monitoring:

The "Network Traffic Over Time" chart will update automatically.

The "Threat Incidents by Type" chart will show increasing counts for "Model Anomaly" as the simulated attack flows are detected.

New "Model Anomaly Detected" alerts will appear in the "Recent Alerts" table.

You will see debug output in your Flask app.py terminal confirming predictions.

Manual Prediction:

In the "Manual Network Flow Anomaly Prediction" section:

Click "Load Example Benign Flow" or "Load Example Attack Flow" to populate the textarea.

Click "Predict Anomaly" to send the data to the backend and see the prediction result below.

7. Current Status / Limitations (Local Version)
Fully Functional Local Prototype: All core components (data processing, model, backend API, frontend dashboard) are working together end-to-end on your local machine.

Simulated Data for Real-time: The real-time alerts are based on a simple random simulation (20% chance of sending an "attack" example, 80% benign) to demonstrate the model's detection capabilities.

Initial Firestore Integration: Alerts can be saved to and loaded from Firestore, providing persistence.

☁️ Cloud Deployment Guide
After setting up and verifying local functionality, proceed to deploy your application to Google Cloud.

1. Google Cloud Project Setup
(This section repeats from above for completeness in deployment context)

Ensure you have a Google Cloud Project: (e.g., tidal-digit-462908-n9).

Ensure Required APIs are Enabled: (Cloud Run API, Cloud Build API, Cloud Firestore API, Identity Toolkit API, Firebase Management API, Firebase Installations API).

2. Firebase Hosting Setup (Continue from Local Setup)
Initialize Firebase CLI locally (if not already done):

In your cybersecurity_project root directory, run firebase init hosting.

Select "Use an existing project" and choose your Firebase project.

For "What do you want to use as your public directory?", type frontend/build.

For "Configure as a single-page app?", type Y.

For overwriting index.html or firebase.json, type N.

Update firebase.json:

Ensure your firebase.json (in the cybersecurity_project root) has the hosting configuration pointing to frontend/build:

{
  "hosting": {
    "public": "frontend/build",
    "ignore": [ "firebase.json", "**/.*", "**/node_modules/**" ],
    "rewrites": [ { "source": "**", "destination": "/index.html" } ]
  }
}

Configure API Key Restrictions (Crucial Troubleshooting Step):

Go to Google Cloud Console -> "APIs & Services" -> "Credentials".

Find the API Key associated with your Firebase web app.

Edit this API Key and:

Under "Application restrictions," select "HTTP referrers (web sites)".

Add your Firebase Hosting domain: https://your-project-id.web.app/* (Replace your-project-id with your actual project ID).

Also add http://localhost:* for local development testing.

Under "API restrictions," select "Restrict key" and ensure Identity Toolkit API, Cloud Firestore API, and Firebase Installations API are all added to the list.

Screenshot Reference: This was a major point of troubleshooting.

Caption: Initial API Key restrictions showing missing Identity Toolkit API.

Caption: Live dashboard showing auth/api-key-not-valid error in console due to incorrect API key restrictions, before fix.

App Check (Ensure it's not blocking during development):

Go to Firebase Console -> "App Check".

Navigate to the "APIs" tab.

Ensure "Authentication [PREVIEW]" and "Cloud Firestore" are set to "Monitoring" or "Unenforced", NOT "Enforced", during development to avoid blocking requests.

Screenshot Reference:

Caption: Firebase App Check APIs tab showing enforcement status.

Caption: Firebase App Check Apps tab (showing webapp registration).

Caption: Firebase App Check showing Authentication in "Monitoring" status.

3. Backend Deployment (Cloud Run)
Ensure app.py has no debug overrides: Confirm the TEMPORARY DEBUG OVERRIDE FOR FORCING ANOMALY section has been removed from your app.py.

Ensure Dockerfile and .dockerignore are in place:

Dockerfile should define your Flask app's container.

.dockerignore should be in the cybersecurity_project root to exclude irrelevant files (like frontend/, data/, venv/, node_modules/, etc.) from the Docker build context.

Build and Deploy the Backend:

Open your terminal and navigate to your cybersecurity_project root directory.

Manually create a compressed archive of ONLY the necessary backend files (this ensures only relevant files are uploaded, bypassing common .dockerignore issues with gcloud builds submit):

tar -czf backend_context.tar.gz Dockerfile app.py anomaly_detection_model.pth minmax_scaler.pkl label_encoders.pkl processed_network_traffic.csv requirements.txt

Submit the archive to Cloud Build:

gcloud builds submit backend_context.tar.gz --tag gcr.io/your-project-id/cybersecurity-backend-service

(Replace your-project-id with your actual Google Cloud Project ID).

Deploy the built image to Cloud Run:

gcloud run deploy cybersecurity-backend-service --image gcr.io/your-project-id/cybersecurity-backend-service --platform managed --region us-central1 --allow-unauthenticated

(Replace your-project-id. us-central1 is your region; ensure consistency).

Note down the Service URL displayed at the end of the gcloud run deploy command (e.g., https://cybersecurity-backend-service-xxxxxxxxxx.us-central1.run.app). You will need this for your frontend.

4. Frontend Deployment (Firebase Hosting)
Update App.jsx (frontend/src/App.jsx):

Replace the firebaseConfig object with the one you copied from the Firebase Console for your project.

Ensure the fetch URL for your backend API points to your deployed Cloud Run service URL.

// Example:
const response = await fetch('https://cybersecurity-backend-service-413007343348.us-central1.run.app/predict', {
// ... (your existing code) ...
});

(Replace the URL with your actual Cloud Run Service URL).

Ensure Firebase initialization prevents duplicate app errors:

import { initializeApp, getApps, getApp } from 'firebase/app';
// ...
let app;
if (!getApps().length) {
  app = initializeApp(firebaseConfig);
} else {
  app = getApp();
}

The useEffect for the Firestore listener should also be robustly guarded (as per the last App.jsx version provided in our chat) to prevent unnecessary warnings.

Build and Deploy the Frontend:

Open your terminal.

Go to the frontend directory: cd frontend

Clean and build: rm -rf build && npm run build

Screenshot Reference: This shows a successful frontend build.

Caption: Terminal output showing successful React frontend build into the build/static directory.

Go back to the project root: cd ..

Deploy to Firebase Hosting: firebase deploy --only hosting

Screenshot Reference: You saw the dashboard working locally after a successful build.

Caption: Frontend dashboard successfully rendered locally at http://localhost:4173/.

✅ Verify Full System Functionality
Once both frontend and backend are deployed:

Open your deployed dashboard URL: https://your-project-id.web.app (Replace your-project-id with your Firebase Hosting URL).

Check the Browser Console: Verify no Firebase initialization or API key errors. You should see messages about Firebase initialization, user authentication, and Firestore listener activity.

Screenshot Reference: This screenshot demonstrates a fully operational system with successful Firebase initialization and Firestore activity.

Caption: Live dashboard showing successful Firebase initialization, user authentication, and Firestore alerts being fetched and added in the console.

Test Manual Anomaly Prediction: Scroll to the "Manual Network Flow Anomaly Prediction" section.

Click "Load Example Attack Flow".

Click "Predict Anomaly".

Observe the "Prediction Result" update, the "Recent Alerts" table showing a new critical alert, and the "Threat Incidents by Type" chart updating. This confirms end-to-end functionality.

Verify Firestore Data: Go to your Firebase Console -> Firestore Database. Navigate to artifacts/default-app-id/users/<YOUR_USER_ID>/alerts to confirm new alerts are being stored and reflect actual model predictions.

Screenshot Reference: This shows alerts saved in Firestore.

Caption: Firestore database showing detected alerts being successfully saved in the collection.

🐛 Key Challenges and Solutions During Development
This project involved overcoming several common but challenging deployment and integration hurdles, which were crucial learning experiences:

Firebase auth/api-key-not-valid Error: This persistent error was due to incorrect API key restrictions (missing Identity Toolkit API permissions and incorrect "HTTP referrers" application restrictions) in Google Cloud Console.

Firebase app/duplicate-app Error: Caused by multiple Firebase initializeApp calls. Resolved by guarding initializeApp with if (!getApps().length).

React App Not Displaying on Firebase Hosting: The frontend/build directory's index.html was not correctly referencing compiled JS/CSS. Fixed by adding base: './' and explicit build.outDir/build.assetsDir to vite.config.js.

gcloud builds submit Upload Timeout (Large Context): The Cloud Build context was too large because .dockerignore was not being reliably honored by gcloud builds submit on your system. Solved by manually creating a .tar.gz archive of only necessary backend files and submitting that archive directly to Cloud Build.

Backend Anomaly Override: A temporary debug feature that forced anomaly predictions was removed from app.py to ensure the model's actual predictions are used, enabling true system validation.

Firestore Listener Warning: A non-critical warning Firestore listener: Firebase (db) or User ID (userId) not ready... was present due to a subtle race condition during initial state updates. While not critical, it can be resolved with more robust state checks for listener setup.

➡️ Future Enhancements
Real-time Data Stream Integration: Integrate with tools like Apache Kafka for handling high-volume, real-time network flow data directly from sources (e.g., actual network taps, log files).

Expanded Threat Categories: Train the model to distinguish between different types of attacks (DDoS, Malware, etc.) beyond just "Anomaly" vs. "Benign."

User Authentication & RBAC: Implement robust user login and role-based access control for different user permissions.

Comprehensive Monitoring: Integrate with tools like Prometheus and Grafana for detailed application and infrastructure performance monitoring.

Formal Unit & Integration Testing: Develop automated tests to ensure code quality and system reliability.

🙏 Acknowledgements
This project was developed with significant guidance and debugging support. The ability to iterate and resolve complex deployment issues, particularly those involving cloud environments and multi-component systems, was crucial for its successful completion.