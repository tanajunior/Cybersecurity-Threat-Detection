
# AI-Enhanced Cybersecurity Threat Detector


This project implements an AI-enhanced Cybersecurity Threat Detection Dashboard designed to monitor network traffic in real-time, detect anomalies using a trained machine learning model, and visualize potential threats. The system comprises a Python Flask backend that serves a deep learning model (Transformer-based) for anomaly prediction and a React frontend that provides an interactive dashboard for real-time monitoring and manual threat analysis.
The system is built to provide early warnings of unusual network behavior, helping administrators identify and respond to potential cyberattacks.





## 🌟 Project Overview



This project is an end-to-end system that covers:

Data Preprocessing Pipeline: Cleans, engineers features, and samples raw network traffic data (CICIDS2017) to prepare it for model training.

Transformer-based Anomaly Detection Model: A PyTorch deep learning model trained to classify network flows as 'Benign' or 'Anomaly'.

Flask REST API Backend: Serves the trained machine learning model, exposing a /predict endpoint for real-time anomaly detection of network flow data. 
It loads and utilizes saved data scalers and label encoders for consistent preprocessing during inference.

React Real-time Dashboard Frontend: An intuitive, visually appealing, and responsive web application that provides:

Automated Polling: Periodically sends simulated network flow data to the Flask backend for continuous real-time threat prediction.

Dynamic Charts: Visualizes "Network Traffic Over Time" and "Threat Incidents by Type" (specifically highlighting 'Model Anomaly' detections).

Live Alerts Table: Populates automatically with "Model Anomaly Detected" alerts as the system identifies unusual traffic patterns.

Notification System: Provides immediate, high-visibility alerts for critical model detections.

Manual Prediction: Allows users to input custom JSON network flow data and receive instant anomaly predictions, aiding in threat analysis.

Firebase Integration: Leverages Google Firebase for:

Authentication: Utilizes anonymous authentication to provide basic user session management, making the application accessible while being extensible for full Role-Based Access Control (RBAC).

Firestore: Enables persistent storage of all detected anomaly alerts, allowing for historical tracking, retrieval, and future analysis of cybersecurity incidents.

The overall system provides a proactive approach to identifying potential network anomalies, ensuring data persistence for analysis, and offering an intuitive monitoring interface.

## Data from
 Network Intrusion dataset(CIC-IDS- 2017) or
 
 https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset

##### Go to: https://www.unb.ca/cic/datasets/ids-2017.html

 

## 🏗️ Architecture

## The project's architecture is divided into three main components:
## 1: Machine Learning Core (Python/PyTorch)
## Data Preprocessing (preprocess_data.py): 
Handles raw network flow data (CICIDS2017), performs essential cleaning (NaNs, infinities), feature  engineering (e.g., packets_per_flow_duration), normalizes numerical features (MinMaxScaler), and encodes categorical features (LabelEncoder). Saves preprocessed data (processed_network_traffic.csv) and preprocessing artifacts (scaler.pkl, label_encoders.pkl) for consistent inference.
## Model Training (train_model.py):
 Defines, trains, and evaluates a Transformer-based neural network for binary classification (Benign/Anomaly). Saves the trained model's weights (anomaly_detection_model.pth)
## 2: Backend API (Flask):
Python Flask Application (app.py): Loads the trained ML model and preprocessing artifacts at application startup. It exposes a /predict REST API endpoint that receives raw network flow data (JSON), preprocesses it using the loaded tools, and returns anomaly predictions.
Containerization (Dockerfile): Packages the Flask application and its Python dependencies into a Docker image for deployment.
Deployment: The Docker image is deployed as a serverless container on Google Cloud Run, providing a scalable and highly available prediction service.

## 3: Frontend Dashboard (React.js):
### React Application: 

A single-page application built with React.js, featuring a dashboard layout with dynamic charts (Chart.js) for network traffic and threat types, and a table for recent alerts.

### Firebase Integration: Utilizes Firebase SDK for:
##### - Authentication:  Anonymous user sign-in to secure access to Firestore.
##### - Firestore: Real-time listeners to fetch historical alerts and functionality to save new alerts detected by the backend.

### Backend Communication: Makes periodic fetch requests to the deployed Flask API for new anomaly predictions.

### Deployment: The React application is built into static assets and deployed on Firebase Hosting.

## 💻 Technologies Used
### Backend (Python):
##### Flask: Web framework for building the API.
##### PyTorch: Deep learning framework for the Transformer model.
##### Pandas: Data manipulation and analysis.
##### Scikit-learn: Data preprocessing (MinMaxScaler, LabelEncoder).
##### Flask-CORS: Handling Cross-Origin Resource Sharing for frontend communication.
##### Pickle: For serializing/deserializing Python objects (model, scalers, encoders).

### Frontend (JavaScript/React):
##### React: JavaScript library for building user interfaces.
##### Vite: Fast build tool for modern web projects.
##### Chart.js / React Chart.js 2: For dynamic and interactive data visualizations.
##### Tailwind CSS: Utility-first CSS framework for styling.
##### Firebase (Auth, Firestore): For user authentication and persistent data storage.

## 📁 Project Structure

```bash
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
```



## 🛠️ Setup and Running Instructions (Local Development)
Follow these steps precisely to set up and run the entire project on your local machine
### Prerequisites
##### Python 3.8+ : Installed on your system.
##### Node.js & npm : Installed on your system (Node.js 14+ recommended).
##### Git (Optional) : For cloning the repository if you were to manage it via Git.
##### Internet Connection : Required for downloading datasets and npm packages.

### Step 1: Project Initialization & Raw Data Acquisition

##### 1 Create Project Directory:
```bash mkdir cybersecurity_project
cd cybersecurityproject (or your project name) 
```

#####  2 Create  Data Directory:
```bash 
mkdir data
```


##### 3 Download CICIDS2017 Dataset:
##### Go to: https://www.unb.ca/cic/datasets/ids-2017.html
Download all eight .pcap_ISCX.csv files listed under "Individual Days CSV Files".
##### Place all downloaded CSV files directly into the cybersecurity_project/data directory. Do not rename them

### Step 2: Data Preprocessing (Python)
#### Create preprocess_data.py:
##### -In the cybersecurity_project directory, create a file named preprocess_data.py.
##### -Paste the content of the preprocess_data.py script into this file.
#### Run Preprocessing Script:
##### -Open a new terminal window.
##### -Navigate to your cybersecurity_project directory:
##### 
```bash  
cd cybersecurity_project
```

Run the script: python preprocess_data.py

##### - Wait for it to complete. It will print messages about loading data, cleaning, and finally "Processed and sampled data successfully saved to: processed_network_traffic.csv".
-This step will also generate minmax_scaler.pkl and label_encoders.pkl.

### Step 3: Model Training (Python)
#### Create train_model.py:
##### In the cybersecurity_project directory, create a file named train_model.py.
Paste the content of the train_model.py script (as provided in our chat history) into this file.
##### Run Model Training Script:
##### Open a new terminal window.
##### Navigate to your cybersecurity_project directory:
```bash  
cd cybersecurity_project
```

Run the script:
python train_model.py


##### This step will take a significant amount of time (approx. 10-20 minutes or more depending on your system, due to 30 epochs and data size). 
Do NOT interrupt it.
##### Verify completion: It will print messages about each epoch's training loss, then evaluation metrics, and finally: "Model saved to: anomaly_detection_model.pth".

### Step 4: Flask Backend Setup (Python)
#### Install Flask-CORS:
In a terminal, ensure you are in the cybersecurity_project directory:
cd cybersecurity_project

- Install the necessary Python package:
- pip install flask-cors  # or pip3 install flask-cors


#### Create app.py:
In the cybersecurity_project directory, create a file named app.py.
- Paste the content of the app.py script (the latest version provided, with the anomaly override removed) into this file.
#### Run Flask Backend Locally:
#####  Open a new terminal window.
#####  Navigate to your cybersecurity_project directory:
```bash  
cd cybersecurity_project
```


#####  Run the server:
```bash
python app.py
```
#####  Verify successful startup: It must print messages about loading the scaler, encoders, and model, and finally: * Running on http://127.0.0.1:5000.
Keep this terminal window open and running.

### Step 5: React Frontend Setup (JavaScript/React)
#### 1: Initialize React Project with Vite:
- Open a new terminal window.
- Navigate to your cybersecurity_project directory:
```bash  
cd cybersecurity_project
```

- Run the Vite command to create the frontend structure:
- npm create vite@latest frontend -- --template react

Follow the prompts: press Enter for project name frontend, select React, then JavaScript + SWC.

#### 2: Navigate to Frontend Directory & Install Dependencies:
- cd frontend
- npm install
- Install specific Chart.js and Firebase dependencies
- npm install chart.js react-chartjs-2 firebase

#### 3:  Place App.jsx Code:
- Navigate to cybersecurity_project/frontend/src/.
- Open App.jsx in your text editor.
- Replace its entire content with the latest App.jsx code (the version with the enhanced Firestore listener readiness and duplicate app check). Save the file

#### 4 Create/Update vite.config.js:
In your frontend/ directory, ensure vite.config.js is configured for relative paths and build output:
- Import { defineConfig } from 'vite'
- Import react from '@vitejs/plugin-react'

```bash
export default defineConfig({
  plugins: [react()],
  base: './', // CRITICAL: Ensures relative paths for assets in the build
  build: {
    outDir: 'build', // Output to 'build' directory
    assetsDir: 'static', // Assets like JS/CSS go into a 'static' subfolder
  }
})
```
### 5 Run React Frontend Locally:
- In the cybersecurity_project/frontend terminal (or a new one, making sure you cd into frontend first):
npm run dev
- Verify successful startup: It will print VITE vX.Y.Z ready in ... ms and ➜ Local: http://localhost:5173/.
- Keep this terminal window open and running.

### 6. How to Use the Dashboard (Local)
- Open your browser and navigate to http://localhost:5173/.
- Observe Real-time Monitoring:
##### - -->The "Network Traffic Over Time" chart will update automatically.
##### - -->The "Threat Incidents by Type" chart will show increasing counts for "Model Anomaly" as the simulated attack flows are detected.
##### - --> New "Model Anomaly Detected" alerts will appear in the "Recent Alerts" table.
##### - --> You will see debug output in your Flask app.py terminal confirming predictions.


### -  Manual Prediction:
- In the "Manual Network Flow Anomaly Prediction" section:
- Click "Load Example Benign Flow" or "Load Example Attack Flow" to populate the textarea.
- Click "Predict Anomaly" to send the data to the backend and see the prediction result below.

### 7. Current Status / Limitations (Local Version)
- Fully Functional Local Prototype: All core components (data processing, model, backend API, frontend dashboard) are working together end-to-end on your local machine.
- Simulated Data for Real-time: The real-time alerts are based on a simple random simulation (20% chance of sending an "attack" example, 80% benign) to demonstrate the model's detection capabilities.
- Initial Firestore Integration: Alerts can be saved to and loaded from Firestore, providing persistence.

## ☁️ Cloud Deployment Guide
After setting up and verifying local functionality, proceed to deploy your application to Google Cloud or your preferred cloud platform.

### 1. Google Cloud Project Setup
- Ensure you have a Google Cloud Project: (e.g., tidal-digit-XXXXX-XX).
- Ensure Required APIs are Enabled: (Cloud Run API, Cloud Build API, Cloud Firestore API, Identity Toolkit API, Firebase Management API, Firebase Installations API).

### 2. Firebase Hosting Setup (Continue from Local Setup)

## - Initialize Firebase CLI locally (if not already done):
#### ->In your cybersecurity_project root directory, run firebase init hosting.
#### ->Select "Use an existing project" and choose your Firebase project.
#### ->For "What do you want to use as your public directory?", type frontend/build.
#### ->For "Configure as a single-page app?", type Y.
#### ->For overwriting index.html or firebase.json, type N.

## - Update firebase.json:
- Ensure your firebase.json (in the cybersecurity_project root) has the hosting configuration pointing to frontend/build:
```bash
{
  "hosting": {
    "public": "frontend/build",
    "ignore": [ "firebase.json", "**/.*", "**/node_modules/**" ],
    "rewrites": [ { "source": "**", "destination": "/index.html" } ]
  }
}
```
## - Configure API Key Restrictions (Crucial Troubleshooting Step):
#### -> Go to Google Cloud Console -> "APIs & Services" -> "Credentials".
#### -> Find the API Key associated with your Firebase web app.
#### -> Edit this API Key and:
#### -> Under "Application restrictions," select "HTTP referrers (web sites)".
#### -> Add your Firebase Hosting domain: https://your-project-id.web.app/* (Replace your-project-id with your actual project ID).
#### -> Also add http://localhost:* for local development testing.
#### -> Under "API restrictions," select "Restrict key" and ensure Identity Toolkit API, Cloud Firestore API, and Firebase Installations API are all added to the list.

##

### - App Check (Ensure it's not blocking during development):
#### -> Ensure "Authentication [PREVIEW]" and "Cloud Firestore" are set to "Monitoring" or "Unenforced", NOT "Enforced", during development to avoid blocking requests.

### 3. Backend Deployment (Cloud Run)
- Ensure app.py has no debug overrides
- Ensure Dockerfile and .dockerignore are in place
- Build and Deploy the Backend
- Submit the archive to Cloud Build
- Deploy the built image to Cloud Run
- Note down the Service URL displayed at the end of the gcloud run deploy command (e.g., https://cybersecurity-backend-service-xxxxxxxxxx.us-central1.run.app). You will need this for your frontend.

### 4. Frontend Deployment (Firebase Hosting)
-Update App.jsx (frontend/src/App.jsx):
- Ensure the fetch URL for your backend API points to your deployed Cloud Run service URL
- Ensure Firebase initialization prevents duplicate app errors:
- The useEffect for the Firestore listener should also be robustly guarded


### Build and Deploy the Frontend:
- Go to the frontend directory: cd frontend
- Clean and build: 
```bash
npm run build
```

- Go back to the project root: cd ..
- Deploy to Firebase Hosting: 
```bash
firebase deploy --only hosting
```


✅ Verify Full System Functionality
 - Once both frontend and backend are deployed:

 - Open your deployed dashboard URL: https://your-project-id.web.app (Replace your-project-id with your Firebase Hosting URL).

Check the Browser Console: Verify no Firebase initialization or API key errors. You should see messages about Firebase initialization, user authentication, and Firestore listener activity.

### - Test Manual Anomaly Prediction: Scroll to the "Manual Network Flow Anomaly Prediction" section. 
#### Click "Load Example Attack Flow".
#### Click "Predict Anomaly".
#### Observe the "Prediction Result" update, the "Recent Alerts" table showing a new critical alert in your firebase database, and the "Threat Incidents by Type" chart updating. This confirms end-to-end functionality.


### 🐛 Key Challenges and Solutions During Development

This project involved overcoming several common but challenging deployment and integration hurdles, which were crucial learning experiences:

#### Firebase auth/api-key-not-valid Error: 
- This error was due to incorrect API key restrictions (missing Identity Toolkit API permissions and incorrect "HTTP referrers" application restrictions) in Google Cloud Console. 
#### Firebase app/duplicate-app Error: 
- Caused by multiple Firebase initializeApp calls. Resolved by guarding initializeApp with if (!getApps().length).
#### React App Not Displaying on Firebase Hosting: 
- The frontend/build directory's index.html was not correctly referencing compiled JS/CSS. Fixed by adding base: './' and explicit build.outDir/build.assetsDir to vite.config.js.

#### gcloud builds submit Upload Timeout (Large Context): 
The Cloud Build context was too large because .dockerignore was not being reliably honored by gcloud builds submit on your system. Solved by manually creating a .tar.gz archive of only necessary backend files and submitting that archive directly to Cloud Build.
#### Backend Anomaly Override: 
- A temporary debug feature that forced anomaly predictions was removed from app.py to ensure the model's actual predictions are used, enabling true system validation.
#### Firestore Listener Warning: A non-critical warning Firestore listener: 
- Firebase (db) or User ID (userId) not ready... was present due to a subtle race condition during initial state updates. While not critical, it can be resolved with more robust state checks for listener setup.



## ➡️ Future Enhancements
#### Real-time Data Stream Integration: 
Integrate with tools like Apache Kafka for handling high-volume, real-time network flow data directly from sources (e.g., actual network taps, log files).
#### Expanded Threat Categories: 
- Train the model to distinguish between different types of attacks (DDoS, Malware, etc.) beyond just "Anomaly" vs. "Benign."
#### User Authentication & RBAC: 
- Implement robust user login and role-based access control for different user permissions.
#### Comprehensive Monitoring: 
- Integrate with tools like Prometheus and Grafana for detailed application and infrastructure performance monitoring.
#### Formal Unit & Integration Testing: 
- Develop automated tests to ensure code quality and system reliability.






####


<div style="background-color: #1a202c; padding: 20px; border-radius: 8px; font-family: 'Inter', sans-serif; display: flex; justify-content: center; align-items: center;">
  <svg width="850" height="650" viewBox="0 0 850 650" fill="none" xmlns="http://www.w3.org/2000/svg">
    <style>
      .node { fill: #2d3748; stroke: #4a5568; stroke-width: 2; rx: 10; ry: 10; }
      .text { font-family: 'Inter', sans-serif; font-size: 15px; fill: #a0aec0; text-anchor: middle; dominant-baseline: central; }
      .title-text { font-family: 'Inter', sans-serif; font-size: 19px; font-weight: bold; fill: #4fd1c5; text-anchor: middle; dominant-baseline: central; }
      .sub-title-text { font-family: 'Inter', sans-serif; font-size: 16px; fill: #63b3ed; text-anchor: middle; dominant-baseline: central; }
      .arrow { stroke: #63b3ed; stroke-width: 2; marker-end: url(#arrowhead); }
      .arrow-dashed { stroke: #a0aec0; stroke-width: 1.5; stroke-dasharray: 5 3; marker-end: url(#arrowhead-dashed); }
      .cloud-box { fill: #234e52; stroke: #4fd1c5; stroke-width: 2; rx: 15; ry: 15; opacity: 0.3; }
      .ml-core { fill: #4a5568; stroke: #e0b355; stroke-width: 2; rx: 10; ry: 10; }
      .db-box { fill: #333d4e; stroke: #9f7aea; stroke-width: 2; rx: 10; ry: 10; }
      .data-box { fill: #2d3748; stroke: #cbd5e0; stroke-width: 2; rx: 10; ry: 10; }
    </style>

    <defs>
      <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="8" refY="3.5" orient="auto">
        <polygon points="0 0, 10 3.5, 0 7" fill="#63b3ed" />
      </marker>
      <marker id="arrowhead-dashed" markerWidth="10" markerHeight="7" refX="8" refY="3.5" orient="auto">
        <polygon points="0 0, 10 3.5, 0 7" fill="#a0aec0" />
      </marker>
    </defs>

    <!-- Google Cloud Platform Boundary -->
    <rect x="250" y="20" width="580" height="610" class="cloud-box"></rect>
    <text x="540" y="45" class="title-text">Google Cloud Platform</text>

    <!-- User -->
    <rect x="50" y="280" width="150" height="60" class="node"></rect>
    <text x="125" y="310" class="text">User / Browser</text>

    <!-- Frontend -->
    <rect x="300" y="100" width="200" height="110" class="node"></rect>
    <text x="400" y="125" class="title-text">Frontend</text>
    <text x="400" y="150" class="text">React.js Application</text>
    <text x="400" y="175" class="sub-title-text">Firebase Hosting</text>

    <!-- Backend API -->
    <rect x="580" y="100" width="200" height="110" class="node"></rect>
    <text x="680" y="125" class="title-text">Backend API</text>
    <text x="680" y="150" class="text">Flask (Python)</text>
    <text x="680" y="175" class="sub-title-text">Cloud Run</text>
    <text x="680" y="195" class="text">(/predict Endpoint)</text>

    <!-- ML Core (Conceptual) -->
    <rect x="580" y="250" width="200" height="70" class="ml-core"></rect>
    <text x="680" y="270" class="title-text">ML Core</text>
    <text x="680" y="295" class="text">PyTorch Transformer Model</text>

    <!-- Cloud Firestore -->
    <rect x="300" y="380" width="200" height="70" class="db-box"></rect>
    <text x="400" y="400" class="title-text">Cloud Firestore</text>
    <text x="400" y="425" class="text">Persistent Alert Storage</text>

    <!-- Firebase Authentication -->
    <rect x="300" y="250" width="200" height="70" class="node"></rect>
    <text x="400" y="270" class="title-text">Firebase Auth</text>
    <text x="400" y="295" class="text">Anonymous Sign-in</text>

    <!-- Raw Data -->
    <rect x="300" y="520" width="180" height="60" class="data-box"></rect>
    <text x="390" y="550" class="text">Raw Data (CICIDS2017)</text>

    <!-- ML Artifacts -->
    <rect x="580" y="520" width="200" height="70" class="data-box"></rect>
    <text x="680" y="540" class="title-text">ML Artifacts</text>
    <text x="680" y="565" class="text">(Model, Scaler, Encoders)</text>

    <!-- Arrows -->

    <!-- User to Frontend -->
    <line x1="200" y1="310" x2="300" y2="155" class="arrow"></line>
    <text x="250" y="250" class="text" fill="#63b3ed" font-size="14">Access Dashboard (HTTP/S)</text>

    <!-- Frontend to Backend API -->
    <line x1="500" y1="155" x2="580" y2="155" class="arrow"></line>
    <text x="540" y="130" class="text" fill="#63b3ed" font-size="14">API Calls (JSON)</text>
    <line x1="580" y1="165" x2="500" y2="165" class="arrow"></line>
    <text x="540" y="190" class="text" fill="#63b3ed" font-size="14">Prediction Response</text>

    <!-- Backend API to ML Core -->
    <line x1="680" y1="210" x2="680" y2="250" class="arrow-dashed"></line>
    <text x="680" y="230" class="text" fill="#a0aec0" font-size="13">Loads/Uses Model</text>

    <!-- Frontend to Firebase Auth -->
    <line x1="400" y1="210" x2="400" y2="250" class="arrow"></line>
    <text x="400" y="230" class="text" fill="#63b3ed" font-size="14">Auth SDK</text>

    <!-- Frontend to Cloud Firestore -->
    <line x1="400" y1="320" x2="400" y2="380" class="arrow"></line>
    <text x="400" y="350" class="text" fill="#63b3ed" font-size="14">Firestore SDK (Read/Write)</text>

    <!-- ML Data to ML Core (Pre-deployment/Setup) -->
    <line x1="390" y1="580" x2="680" y2="310" class="arrow-dashed"></line>
    <text x="485" y="470" class="text" fill="#a0aec0" font-size="14">Preprocess & Train</text>

    <!-- ML Artifacts to ML Core (Deployment/Runtime) -->
    <line x1="680" y1="520" x2="680" y2="320" class="arrow-dashed"></line>
    <text x="680" y="420" class="text" fill="#a0aec0" font-size="14">Loaded by Backend (Runtime)</text>

    <!-- Labels for ML Data/Artifacts -->
    <text x="390" y="500" class="text" fill="#a0aec0" font-size="12">Used for preprocessing & training</text>
    <text x="680" y="480" class="text" fill="#a0aec0" font-size="12">Result of preprocessing & training</text>

  </svg>
</div>





































