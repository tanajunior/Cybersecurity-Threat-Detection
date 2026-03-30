# 🛡️ AI-Enhanced Cybersecurity Threat Detection Dashboard

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)
![PyTorch](https://img.shields.io/badge/PyTorch-Transformer_Model-EE4C2C?style=flat&logo=pytorch&logoColor=white)
![React](https://img.shields.io/badge/React-Dashboard-61DAFB?style=flat&logo=react&logoColor=black)
![Flask](https://img.shields.io/badge/Flask-REST_API-000000?style=flat&logo=flask&logoColor=white)
![Firebase](https://img.shields.io/badge/Firebase-Hosting_+_Firestore-FFCA28?style=flat&logo=firebase&logoColor=black)
![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED?style=flat&logo=docker&logoColor=white)
![Cloud Run](https://img.shields.io/badge/Google_Cloud_Run-Deployed-4285F4?style=flat&logo=google-cloud&logoColor=white)

> A fully deployed, end-to-end AI system that monitors network traffic in real time, detects anomalies using a Transformer-based deep learning model, and visualizes threats through an interactive React dashboard — backed by Firebase and deployed on Google Cloud.

---

## 📸 Screenshots

### Threat Detection Dashboard
![Threat Dashboard](threat%20dashboard.png)

### Flow Anomaly Prediction
![Flow Anomaly Prediction](%20Flow%20Anomaly%20Prediction.jpg)

### Firestore Alert Logs
![Alerts Firestore](Alerts%20Logs%20firestore%20database.png)

---

## 🌟 What This Project Demonstrates

- **Deep Learning in Production** — Transformer-based PyTorch model trained on real network intrusion data (CICIDS2017), served via a REST API
- **Full-stack Engineering** — React frontend + Flask backend, fully integrated
- **Cloud Deployment** — Backend on Google Cloud Run (Docker), frontend on Firebase Hosting
- **Real-time Data Pipeline** — Live polling, dynamic Chart.js visualizations, and Firestore persistence
- **DevOps Practices** — Dockerized backend, CI/CD-ready structure, environment-separated config

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   React Dashboard                        │
│         (Firebase Hosting — your-project.web.app)        │
│                                                          │
│  ┌──────────────┐  ┌─────────────────┐  ┌────────────┐  │
│  │ Traffic Chart│  │ Threat Incidents │  │Alert Table │  │
│  └──────┬───────┘  └────────┬────────┘  └─────┬──────┘  │
└─────────┼───────────────────┼─────────────────┼─────────┘
          │     REST API      │                 │
          ▼     /predict      │           Firestore
┌─────────────────────┐       │        ┌──────────────────┐
│   Flask Backend     │       │        │  Firebase        │
│   (Google Cloud Run)│       │        │  Firestore DB    │
│                     │       └───────►│  (Alert Logs)    │
│  PyTorch Transformer│                └──────────────────┘
│  Anomaly Detector   │
│  MinMaxScaler       │
│  LabelEncoder       │
└─────────────────────┘
         ▲
         │ Trained on
┌─────────────────────┐
│  CICIDS2017 Dataset │
│  Network Traffic    │
│  (Real intrusion    │
│   data — UNB)       │
└─────────────────────┘
```

---

## 🧠 ML Model Details

| Property | Detail |
|---|---|
| Architecture | Transformer-based neural network |
| Framework | PyTorch |
| Task | Binary classification (Benign / Anomaly) |
| Dataset | CICIDS2017 — Canadian Institute for Cybersecurity |
| Preprocessing | MinMaxScaler + LabelEncoder (saved as `.pkl`) |
| Training | 30 epochs, CPU/GPU compatible |
| Output | Trained model saved as `anomaly_detection_model.pth` |

---

## 💻 Tech Stack

| Layer | Technologies |
|---|---|
| ML / Backend | Python, PyTorch, Flask, Pandas, Scikit-learn |
| Frontend | React, Vite, Chart.js, Tailwind CSS |
| Database | Firebase Firestore |
| Auth | Firebase Anonymous Auth |
| Containerization | Docker |
| Cloud | Google Cloud Run, Firebase Hosting |
| Data | CICIDS2017 (UNB Network Intrusion Dataset) |

---

## 📁 Project Structure

```
cybersecurity-threat-detection/
├── data/                          # CICIDS2017 raw CSV files (not committed)
├── frontend/
│   ├── src/
│   │   ├── App.jsx                # Main React dashboard
│   │   └── main.jsx
│   ├── vite.config.js
│   └── package.json
├── app.py                         # Flask API — serves predictions
├── train_model.py                 # Model training script
├── preprocess_data.py             # Data cleaning + feature engineering
├── anomaly_detection_model.pth    # Trained model weights
├── minmax_scaler.pkl              # Fitted scaler for inference
├── label_encoders.pkl             # Fitted encoders for inference
├── Dockerfile                     # Backend containerization
├── requirements.txt               # Python dependencies
└── firebase.json                  # Firebase Hosting config
```

---

## 🚀 Quick Start (Local)

### Prerequisites
- Python 3.8+
- Node.js 14+
- Google Cloud account (for full deployment)

### 1. Clone and set up backend
```bash
git clone https://github.com/tanajunior/Cybersecurity-Threat-Detection.git
cd Cybersecurity-Threat-Detection
pip install -r requirements.txt
```

### 2. Download dataset
Get CICIDS2017 CSV files from [UNB](https://www.unb.ca/cic/datasets/ids-2017.html) or [Kaggle](https://www.kaggle.com/datasets/chethuhn/network-intrusion-dataset) and place in `/data`.

### 3. Preprocess and train
```bash
python preprocess_data.py   # ~5 min
python train_model.py       # ~15-20 min
```

### 4. Run Flask API
```bash
python app.py
# Running on http://127.0.0.1:5000
```

### 5. Run React frontend
```bash
cd frontend
npm install
npm install chart.js react-chartjs-2 firebase
npm run dev
# Open http://localhost:5173
```

---

## ☁️ Deployment

| Component | Platform | Command |
|---|---|---|
| Backend | Google Cloud Run | `gcloud run deploy` |
| Frontend | Firebase Hosting | `firebase deploy --only hosting` |
| Database | Firebase Firestore | Auto-provisioned |

See [full deployment guide](#) in the wiki for step-by-step Cloud Run + Firebase setup.

---

## 🔭 Roadmap

- [ ] Real-time Kafka stream integration for live network feeds
- [ ] Multi-class threat classification (DDoS, Malware, Brute Force, etc.)
- [ ] Full RBAC user authentication
- [ ] Prometheus + Grafana monitoring integration
- [ ] Automated model retraining pipeline

---

## 👤 Author

**Junior Tana**
DevOps Engineer | CS Student @ University of the People

[![GitHub](https://img.shields.io/badge/GitHub-tanajunior-181717?style=flat&logo=github)](https://github.com/tanajunior)

---

## 📄 License

MIT License
