import React, { useState, useEffect, useCallback } from 'react';
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend, LineElement, PointElement, ArcElement } from 'chart.js';
import { Bar, Line } from 'react-chartjs-2';
import { getAuth, signInAnonymously, signInWithCustomToken, onAuthStateChanged } from 'firebase/auth';
import { initializeApp, getApps, getApp } from 'firebase/app'; // Import getApps and getApp
import { getFirestore, collection, onSnapshot, addDoc } from 'firebase/firestore'; // addDoc is now included

// Register Chart.js components
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  LineElement,
  PointElement,
  ArcElement
);

// Helper function to generate a random number within a range
const getRandomInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

// Initial data for charts
const initialTrafficData = {
  labels: ['0s', '10s', '20s', '30s', '40s', '50s', '60s'], // Time-based labels
  datasets: [
    {
      label: 'Inbound Traffic (MB)',
      data: [0, 0, 0, 0, 0, 0, 0],
      borderColor: 'rgb(75, 192, 192)',
      backgroundColor: 'rgba(75, 192, 192, 0.5)',
      tension: 0.3,
    },
    {
      label: 'Outbound Traffic (MB)',
      data: [0, 0, 0, 0, 0, 0, 0],
      borderColor: 'rgb(255, 99, 132)',
      backgroundColor: 'rgba(255, 99, 132, 0.5)',
      tension: 0.3,
    },
  ],
};

const initialThreatTypeData = {
  labels: ['Malware', 'DDoS', 'Phishing', 'Insider Threat', 'Port Scan', 'SQL Injection', 'Model Anomaly'],
  datasets: [
    {
      label: '# of Incidents',
      data: [0, 0, 0, 0, 0, 0, 0], // Initialize all counts to 0
      backgroundColor: [
        'rgba(255, 99, 132, 0.6)', 'rgba(54, 162, 235, 0.6)', 'rgba(255, 206, 86, 0.6)',
        'rgba(75, 192, 192, 0.6)', 'rgba(153, 102, 255, 0.6)', 'rgba(255, 159, 64, 0.6)',
        'rgba(255, 64, 64, 0.6)' // Color for Model Anomaly
      ],
      borderColor: [
        'rgba(255, 99, 132, 1)', 'rgba(54, 162, 235, 1)', 'rgba(255, 206, 86, 1)',
        'rgba(75, 192, 192, 1)', 'rgba(153, 102, 255, 1)', 'rgba(255, 159, 64, 1)',
        'rgba(255, 64, 64, 1)' // Border color for Model Anomaly
      ],
      borderWidth: 1,
    },
  ],
};

// --- Main App component ---
const App = () => {
  const [alerts, setAlerts] = useState([]);
  const [trafficData, setTrafficData] = useState(initialTrafficData);
  const [threatTypeData, setThreatTypeData] = useState(initialThreatTypeData);
  const [db, setDb] = useState(null);
  const [auth, setAuth] = useState(null);
  const [userId, setUserId] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [notification, setNotification] = useState(null);
  const [isFirebaseReady, setIsFirebaseReady] = useState(false); // New state for Firebase readiness

  // State for API prediction (for manual testing section)
  const [flowInput, setFlowInput] = useState('');
  const [predictionResult, setPredictionResult] = useState(null);
  const [predictionLoading, setPredictionLoading] = useState(false);
  const [predictionError, setPredictionError] = useState(null);

  // Example network flow data (must match features expected by your Flask backend)
  // Ensure all 79 features (or whatever GLOBAL_INPUT_FEATURES_ORDER determines) are present.
  const exampleBenignFlow = JSON.stringify({
    "destination_port": 53, "flow_duration": 63973979, "total_fwd_packets": 6, "total_backward_packets": 2,
    "total_length_of_fwd_packets": 204, "total_length_of_bwd_packets": 172, "fwd_packet_length_max": 34,
    "fwd_packet_length_min": 34, "fwd_packet_length_mean": 34, "fwd_packet_length_std": 0,
    "bwd_packet_length_max": 86, "bwd_packet_length_min": 86, "bwd_packet_length_mean": 86,
    "bwd_packet_length_std": 0, "flow_bytes_s": 58.784013, "flow_packets_s": 0.125049,
    "flow_iat_mean": 21324659.67, "flow_iat_std": 36940847.05, "flow_iat_max": 63897455,
    "flow_iat_min": 76524, "fwd_iat_total": 63973979, "fwd_iat_mean": 12794795.8,
    "fwd_iat_std": 28593457.7, "fwd_iat_max": 63897455, "fwd_iat_min": 76524,
    "bwd_iat_total": 87799, "bwd_iat_mean": 87799, "bwd_iat_std": 0, "bwd_iat_max": 87799,
    "bwd_iat_min": 87799, "fwd_psh_flags": 0, "bwd_psh_flags": 0, "fwd_urg_flags": 0,
    "bwd_urg_flags": 0, "fwd_header_length": 128, "bwd_header_length": 64,
    "fwd_packets_s": 0.093786, "bwd_packets_s": 0.031262, "min_packet_length": 34,
    "max_packet_length": 86, "packet_length_mean": 47.777778, "packet_length_std": 20.301548,
    "packet_length_variance": 412.148148, "fin_flag_count": 0, "syn_flag_count": 0, "rst_flag_count": 0,
    "psh_flag_count": 0, "ack_flag_count": 0, "urg_flag_count": 0, "cwe_flag_count": 0,
    "ece_flag_count": 0, "down_up_ratio": 0.333333, "average_packet_size": 53.75,
    "avg_fwd_segment_size": 34, "avg_bwd_segment_size": 86, "fwd_header_length1": 128,
    "fwd_avg_bytes_bulk": 0, "fwd_avg_packets_bulk": 0, "fwd_avg_bulk_rate": 0,
    "bwd_avg_bytes_bulk": 0, "bwd_avg_packets_bulk": 0, "bwd_avg_bulk_rate": 0,
    "subflow_fwd_packets": 6, "subflow_fwd_bytes": 204, "subflow_bwd_packets": 2,
    "subflow_bwd_bytes": 172, "init_win_bytes_forward": 29200, "init_win_bytes_backward": 29200,
    "act_active_mean": 0, "act_active_std": 0, "act_active_max": 0, "act_active_min": 0,
    "min_fl_iat": 76524, "max_fl_iat": 63897455, "std_fl_iat": 36940847.05,
    "fwd_init_win_bytes": 29200, "bwd_init_win_bytes": 29200, "active_mean": 0, "active_std": 0,
    "active_max": 0, "active_min": 0, "idle_mean": 0, "idle_std": 0, "idle_max": 0, "idle_min": 0,
    "packets_per_flow_duration": 0.0,
    "act_data_pkt_fwd": 0,
    "min_seg_size_forward": 0
  });

  // RAW example attack flow data (TRULY EXTREME values to trigger anomaly)
  // Ensure all 79 features (or whatever GLOBAL_INPUT_FEATURES_ORDER determines) are present.
  const exampleAttackFlow = JSON.stringify({
    "destination_port": 80, "flow_duration": 10, "total_fwd_packets": 50000, "total_backward_packets": 0,
    "total_length_of_fwd_packets": 10000000, "total_length_of_bwd_packets": 0, "fwd_packet_length_max": 200,
    "fwd_packet_length_min": 200, "fwd_packet_length_mean": 200, "fwd_packet_length_std": 0,
    "bwd_packet_length_max": 0, "bwd_packet_length_min": 0, "bwd_packet_length_mean": 0,
    "bwd_packet_length_std": 0, "flow_bytes_s": 1000000000, "flow_packets_s": 2500000,
    "flow_iat_mean": 0.001, "flow_iat_std": 0, "flow_iat_max": 0.001, "flow_iat_min": 0.001,
    "fwd_iat_total": 10, "fwd_iat_mean": 0.001, "fwd_iat_std": 0, "fwd_iat_max": 0.001,
    "fwd_iat_min": 0.001, "bwd_iat_total": 0, "bwd_iat_mean": 0, "bwd_iat_std": 0,
    "bwd_iat_max": 0, "bwd_iat_min": 0, "fwd_psh_flags": 0, "bwd_psh_flags": 0, "fwd_urg_flags": 0,
    "bwd_urg_flags": 0, "fwd_header_length": 200000, "bwd_header_length": 0,
    "fwd_packets_s": 2500000, "bwd_packets_s": 0, "min_packet_length": 200, "max_packet_length": 200,
    "packet_length_mean": 200, "packet_length_std": 0, "packet_length_variance": 0, "fin_flag_count": 0,
    "syn_flag_count": 1, "rst_flag_count": 0, "psh_flag_count": 0, "ack_flag_count": 0, "urg_flag_count": 0,
    "cwe_flag_count": 0, "ece_flag_count": 0, "down_up_ratio": 0, "average_packet_size": 200,
    "avg_fwd_segment_size": 200, "avg_bwd_segment_size": 0, "fwd_header_length1": 200000,
    "fwd_avg_bytes_bulk": 0, "fwd_avg_packets_bulk": 0, "fwd_avg_bulk_rate": 0,
    "bwd_avg_bytes_bulk": 0, "bwd_avg_packets_bulk": 0, "bwd_avg_bulk_rate": 0,
    "subflow_fwd_packets": 50000, "subflow_fwd_bytes": 10000000, "subflow_bwd_packets": 0,
    "subflow_bwd_bytes": 0, "init_win_bytes_forward": -1, "init_win_bytes_backward": -1,
    "act_active_mean": 0, "act_active_std": 0, "act_active_max": 0, "act_active_min": 0,
    "min_fl_iat": 0, "max_fl_iat": 0, "std_fl_iat": 0, "fwd_init_win_bytes": -1, "bwd_init_win_bytes": -1,
    "active_mean": 0, "active_std": 0, "active_max": 0, "active_min": 0, "idle_mean": 0,
    "idle_std": 0, "idle_max": 0, "idle_min": 0,
    "packets_per_flow_duration": 5000000,
    "act_data_pkt_fwd": 50000,
    "min_seg_size_forward": 200
  });


  // Helper function for loading example flows into the textarea
  const loadExampleFlow = (type) => {
    if (type === 'benign') {
      setFlowInput(exampleBenignFlow);
    } else if (type === 'attack') {
      setFlowInput(exampleAttackFlow);
    }
    setPredictionResult(null); // Clear previous prediction result
    setPredictionError(null);  // Clear previous error
  };


  // Firebase setup and authentication
  useEffect(() => {
    try {
      // Your web app's Firebase configuration - DIRECTLY FROM YOUR CONSOLE
    const firebaseConfig = {
        apiKey: "AIzaSyDcEBOOctKNY368AGyrasHS3LCD0IjCvDw", 
        authDomain: "tidal-digit-462908-n9.firebaseapp.com",
        databaseURL: "https://tidal-digit-462908-n9-default-rtdb.firebaseio.com",
        projectId: "tidal-digit-462908-n9",
        storageBucket: "tidal-digit-462908-n9.firebasestorage.app",
        messagingSenderId: "413007343348",
        appId: "1:413007343348:web:178f56e6aba0c2c36ab8a1"
      };

      let app;
      // Check if Firebase app already exists to prevent duplicate initialization
      if (!getApps().length) {
        app = initializeApp(firebaseConfig);
        console.log("Firebase app initialized successfully for the first time!");
      } else {
        app = getApp(); // If already initialized, get the existing app
        console.log("Firebase app already initialized, retrieving existing app.");
      }

      // Add a final check for API key presence (though it should be fine with direct config now)
      if (!firebaseConfig.apiKey) {
          console.error("Firebase API Key is missing! Cannot initialize Firebase.");
          setIsLoading(false);
          return; // Exit useEffect early if API key is missing
      }
      
      const firestore = getFirestore(app);
      const firebaseAuth = getAuth(app);
      setDb(firestore);
      setAuth(firebaseAuth);
      console.log("Firestore and Auth instances set."); // DEBUG LOG

      const unsubscribe = onAuthStateChanged(firebaseAuth, async (user) => {
        if (user) {
          setUserId(user.uid);
          console.log("User authenticated:", user.uid); // DEBUG LOG
        } else {
          try {
            const anonUserCredential = await signInAnonymously(firebaseAuth);
            setUserId(anonUserCredential.user.uid);
            console.log("Signed in anonymously:", anonUserCredential.user.uid); // DEBUG LOG
          } catch (error) {
            console.error("Error signing in anonymously:", error);
          }
        }
        // Set isLoading to false and isFirebaseReady to true ONLY AFTER user ID is set
        setIsLoading(false);
        setIsFirebaseReady(true); // Firebase is now ready (db, auth, userId are available)
      });

      // Handle initial auth token if provided by the environment (if applicable)
      // This part is for Canvas environment; it might not be relevant for local testing
      if (typeof __initial_auth_token !== 'undefined' && firebaseAuth && !firebaseAuth.currentUser) {
        signInWithCustomToken(firebaseAuth, __initial_auth_token)
          .then((userCredential) => {
            console.log("Signed in with custom token:", userCredential.user.uid);
          })
          .catch((error) => {
            console.error("Error signing in with custom token:", error);
            // Fallback to anonymous if custom token fails
            if (!firebaseAuth.currentUser) {
              signInAnonymously(firebaseAuth)
                .then((userCredential) => {
                  setUserId(userCredential.user.uid);
                  setIsFirebaseReady(true); // Firebase is now ready
                })
                .catch((anonError) => console.error("Error signing in anonymously (fallback):", anonError));
            }
          })
          .finally(() => setIsLoading(false)); // Ensure loading state is cleared
      } else if (!firebaseAuth.currentUser) {
        // If no custom token, sign in anonymously
        signInAnonymously(firebaseAuth)
          .then((userCredential) => {
            setUserId(userCredential.user.uid);
            setIsFirebaseReady(true); // Firebase is now ready
          })
          .catch((error) => console.error("Error signing in anonymously:", error))
          .finally(() => setIsLoading(false)); // Ensure loading state is cleared
      }

      return () => unsubscribe(); // Cleanup auth listener on component unmount
    } catch (error) {
      console.error("Failed to initialize Firebase:", error);
      setIsLoading(false); // Ensure loading state is cleared even if Firebase init fails
    }
  }, []); // Empty dependency array means this effect runs once on mount


  // --- API Prediction Logic (Refactored for reusability) ---
  const handlePredict = useCallback(async (flowDataOverride = null) => {
    const dataToSend = flowDataOverride ? flowDataOverride : flowInput;

    // Log the data being sent for debugging
    console.log("Data being sent to API:", dataToSend ? JSON.parse(dataToSend) : "No data (manual trigger)");

    if (!dataToSend) {
      if (!flowDataOverride) { // Only show error for manual input button click
        setPredictionError("No network flow JSON data provided. Please load an example or enter data.");
      }
      return null;
    }
    
    if (!flowDataOverride) { // Only update prediction UI state if triggered manually
      setPredictionLoading(true);
      setPredictionResult(null);
      setPredictionError(null);
    }

    try {
      const parsedInput = JSON.parse(dataToSend); // Parse JSON string to object

      // THIS IS THE ABSOLUTELY CORRECTED API ENDPOINT CALL
      const response = await fetch('https://cybersecurity-backend-service-413007343348.us-central1.run.app/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(parsedInput), // Send the JSON object as string
      });

      if (!response.ok) {
        // If response status is not 2xx, parse error from backend
        const errorData = await response.json();
        throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
      }

      const data = await response.json(); // Parse successful response

      // Aggressive cleaning of prediction label string (e.g., remove hidden chars)
      const cleanedPredictionLabel = String(data.prediction)
                                    .normalize("NFC") // Unicode normalization
                                    .replace(/[^a-zA-Z]/g, '') // Remove non-alphabetic characters
                                    .trim() // Trim whitespace
                                    .toLowerCase(); // Convert to lowercase
      
      const displayLabel = (cleanedPredictionLabel === 'anomaly') ? 'Anomaly' : 'Benign';

      const result = {
        prediction: displayLabel,
        anomaly_probability: data.anomaly_probability
      };

      if (!flowDataOverride) { // Only update predictionResult state if manual trigger
        setPredictionResult(result);
      }
      return result; // Return the result for automated polling
    } catch (error) {
      // Generic error handling for deployed API calls
      if (!flowDataOverride) {
          setPredictionError(`Prediction failed: ${error.message || "An unknown network error occurred."}`);
      }
      console.error("Prediction API error:", error);
      return null;
    } finally {
      if (!flowDataOverride) { // Only clear loading state if manually triggered
        setPredictionLoading(false);
      }
    }
  }, [flowInput]); // Dependency on flowInput for the manual prediction part


  // --- Automated Real-time API Polling and Dashboard Updates ---
  // This useEffect now DEPENDS on isFirebaseReady
  useEffect(() => {
    let pollingInterval;
    if (isFirebaseReady) { // Only start polling if Firebase is fully initialized
      pollingInterval = setInterval(async () => {
        // Randomly choose between benign and attack flow for automated polling
        // 20% chance of an "attack" flow being sent to simulate anomalies
        const flowToPredict = Math.random() < 0.2 ? exampleAttackFlow : exampleBenignFlow;
        
        const predictionResponse = await handlePredict(flowToPredict); // Call API with override data
        
        if (predictionResponse) {
          // Update Network Traffic Data (simulated increase every interval)
          setTrafficData(prevData => {
            const newInbound = prevData.datasets[0].data.slice(1); // Remove oldest data point
            newInbound.push(getRandomInt(100, 500)); // Add new random inbound traffic
            const newOutbound = prevData.datasets[1].data.slice(1); // Remove oldest data point
            newOutbound.push(getRandomInt(80, 450)); // Add new random outbound traffic
            const newLabels = prevData.labels.slice(1); // Shift time labels
            const lastTimeLabel = prevData.labels.length > 0 ? parseInt(prevData.labels[prevData.labels.length - 1].replace('s', '')) : -10;
            newLabels.push(`${lastTimeLabel + 10}s`); // Increment time labels by 10 seconds

            return {
              labels: newLabels,
              datasets: [
                { ...prevData.datasets[0], data: newInbound },
                { ...prevData.datasets[1], data: newOutbound },
              ],
            };
          });

          // If prediction from Flask API is 'Anomaly', generate an alert and update threat type chart
          if (predictionResponse.prediction === 'Anomaly') {
            const newAlert = {
              id: `alert-${Date.now()}-${getRandomInt(0, 1000)}`, // Unique ID for the alert
              type: 'Model Anomaly Detected', // Specific type for model-generated alerts
              severity: parseFloat(predictionResponse.anomaly_probability) > 0.8 ? 'Critical' : 'High', // Severity based on probability
              timestamp: new Date().toLocaleString(), // Current local date and time
              sourceIp: `Sim.${getRandomInt(1, 255)}.${getRandomInt(1, 255)}.${getRandomInt(1, 255)}`, // Simulated Source IP
              destinationIp: `Dest.${getRandomInt(1, 255)}.${getRandomInt(1, 255)}.${getRandomInt(1, 255)}`, // Simulated Destination IP
              status: 'Active', // New alerts are active
              modelProbability: predictionResponse.anomaly_probability // Include model's probability
            };

            // --- Firestore: Save new alert to database ---
            // This 'if (db && userId)' check is still good practice, but now
            // the whole effect only runs when they are ready.
            if (db && userId) {
              const appId = typeof __app_id !== 'undefined' ? __app_id : 'default-app-id';
              const alertsCollectionRef = collection(db, `artifacts/${appId}/users/${userId}/alerts`);
              console.log("Attempting to add alert to Firestore path:", alertsCollectionRef.path); // DEBUG LOG
              try {
                await addDoc(alertsCollectionRef, newAlert);
                console.log("Alert successfully added to Firestore:", newAlert.id);
              } catch (error) {
                console.error("Error adding alert to Firestore:", error); // Specific error from addDoc
              }
            } else {
              console.warn("Firestore (db) or User ID (userId) not ready during polling loop. This should not happen if isFirebaseReady is true."); // Should rarely see this now
            }
            // --- End Firestore save ---

            setAlerts(prevAlerts => {
              const updatedAlerts = [newAlert, ...prevAlerts]; // Add new alert to the top
              return updatedAlerts.slice(0, 10); // Keep only the 10 most recent alerts
            });

            // Show a temporary notification banner for critical/high alerts
            if (newAlert.severity === 'Critical' || newAlert.severity === 'High') {
              setNotification({
                message: `${newAlert.severity} Alert: ${newAlert.type} (Prob: ${newAlert.modelProbability})`,
                type: newAlert.severity,
              });
              setTimeout(() => setNotification(null), 5000); // Hide notification after 5 seconds
            }

            // Update Threat Type Data for 'Model Anomaly' category
            setThreatTypeData(prevData => {
              const updatedCounts = [...prevData.datasets[0].data];
              const threatIndex = prevData.labels.indexOf('Model Anomaly'); // Find index of 'Model Anomaly'
              if (threatIndex !== -1) {
                updatedCounts[threatIndex] += 1; // Increment its count
              } else {
                // Fallback: If 'Model Anomaly' label is somehow missing, add it and its count
                console.warn("'Model Anomaly' label not found in chart data. Adding it dynamically.");
                prevData.labels.push('Model Anomaly');
                updatedCounts.push(1);
                prevData.datasets[0].backgroundColor.push('rgba(255, 64, 64, 0.6)');
                prevData.datasets[0].borderColor.push('rgba(255, 64, 64, 1)');
              }
              return {
                ...prevData,
                datasets: [{ ...prevData.datasets[0], data: updatedCounts }],
              };
            });
          }
        }

      }, 5000); // Poll Flask API every 5 seconds
    }

    return () => {
      if (pollingInterval) {
        clearInterval(pollingInterval); // Cleanup interval on component unmount or when isFirebaseReady becomes false
      }
    };
  }, [isFirebaseReady, db, userId, handlePredict, exampleAttackFlow, exampleBenignFlow]); // Dependencies now include isFirebaseReady, db, userId


  // Firebase alert fetching (for persistent historical alerts)
  // This useEffect also DEPENDS on isFirebaseReady
  useEffect(() => {
    let unsubscribe;
    if (isFirebaseReady && db && userId) { // Only set up listener if Firebase is fully initialized
      const appId = typeof __app_id !== 'undefined' ? __app_id : 'default-app-id';
      console.log("Firestore listener active for path:", `artifacts/${appId}/users/${userId}/alerts`); // DEBUG LOG
      const alertsCollectionRef = collection(db, `artifacts/${appId}/users/${userId}/alerts`);

      unsubscribe = onSnapshot(alertsCollectionRef, (snapshot) => {
        const fetchedAlerts = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        console.log("Fetched historical alerts from Firestore:", fetchedAlerts.length, "alerts."); // DEBUG LOG
        // Now populating the main alerts table from Firestore
        setAlerts(fetchedAlerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))); // Sort by most recent first
      }, (error) => {
        console.error("Error listening to alerts from Firestore:", error);
      });
    } else {
      console.warn("Firestore listener: Firebase (db) or User ID (userId) not ready, or isFirebaseReady is false. Cannot set up listener for historical alerts."); // Should rarely see this now
    }
    return () => {
      if (unsubscribe) {
        unsubscribe(); // Unsubscribe on component cleanup or when dependencies change
      }
    };
  }, [isFirebaseReady, db, userId]); // Dependencies for Firestore listener now include isFirebaseReady


  // Chart Options (ensure font-family is 'Inter' for consistent styling)
  const chartFont = { family: 'Inter', size: 14 };
  const titleFont = { family: 'Inter', size: 18, weight: 'bold' };

  const barOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { position: 'top', labels: { font: chartFont } },
      title: { display: true, text: 'Threat Incidents by Type', font: titleFont },
      tooltip: {
        callbacks: {
          label: function(context) {
            let label = context.dataset.label || '';
            if (label) { label += ': '; }
            if (context.parsed.y !== null) { label += context.parsed.y; }
            return context.label + ': ' + context.parsed.y;
          }
        },
        titleFont: chartFont,
        bodyFont: chartFont,
      },
    },
    scales: {
      x: { ticks: { font: chartFont } },
      y: { beginAtZero: true, ticks: { font: chartFont } },
    },
  };

  const lineOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { position: 'top', labels: { font: chartFont } },
      title: { display: true, text: 'Network Traffic Over Time', font: titleFont },
      tooltip: {
        callbacks: {
          label: function(context) {
            let label = context.dataset.label || '';
            if (label) { label += ': '; }
            if (context.parsed.y !== null) { label += context.parsed.y + ' MB'; }
            return label;
          }
        },
        titleFont: chartFont,
        bodyFont: chartFont,
      },
    },
    scales: {
      x: { ticks: { font: chartFont } },
      y: { beginAtZero: true, ticks: { font: chartFont } },
    },
  };

  // If loading, display a simple loading message
  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-900 text-white text-xl font-inter">
        Loading dashboard...
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-900 text-white font-inter p-6 md:p-10">
      {/* Tailwind CSS and Inter font import for consistent styling */}
      <style>
        {`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; }
        .font-inter { font-family: 'Inter', sans-serif; }
        `}
      </style>
      
      {/* Header Section */}
      <header className="mb-8 text-center md:text-left">
        <h1 className="text-4xl md:text-5xl font-bold text-teal-400 mb-2">
          Cybersecurity Threat Dashboard
        </h1>
        <p className="text-xl text-gray-400">Proactive Anomaly Detection & Threat Prediction</p>
        {userId && (
          <p className="text-sm text-gray-500 mt-2">
            User ID: <span className="font-mono bg-gray-800 px-2 py-1 rounded-md">{userId}</span>
          </p>
        )}
      </header>

      {/* Notification Banner for Critical/High Alerts */}
      {notification && (
        <div
          className={`fixed top-4 right-4 z-50 p-4 rounded-lg shadow-xl text-white
                      ${notification.type === 'Critical' ? 'bg-red-700' : 'bg-orange-600'}`}
          role="alert"
        >
          <div className="flex items-center">
            <svg
              className="w-6 h-6 mr-3"
              fill="currentColor"
              viewBox="0 0 20 20"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                fillRule="evenodd"
                d="M18.259 13.914a1 1 0 00-.097-1.403l-4.5-4.5a1 1 0 00-1.414 0l-4.5 4.5a1 1 0 00-.097 1.403 1 1 0 001.403.097L10 11.414l3.544 3.543a1 1 0 001.403-.097zM8.707 5.707a1 1 0 00-1.414 0l-4.5 4.5a1 1 0 00-.097 1.403 1 1 0 001.403.097L7 8.414l3.544 3.543a1 1 0 001.403-.097 1 1 0 00-.097-1.403l-4.5-4.5a1 1 0 00-1.414 0z"
                clipRule="evenodd"
              ></path>
            </svg>
            <p className="font-semibold">{notification.message}</p>
          </div>
        </div>
      )}

      {/* Overview Cards Section */}
      <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-10">
        <div className="bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-700 flex flex-col items-center justify-center text-center transform hover:scale-105 transition-transform duration-300">
          <h2 className="text-2xl font-semibold text-teal-300 mb-2">Total Alerts</h2>
          <p className="text-5xl font-bold text-red-500">{alerts.length}</p>
        </div>
        <div className="bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-700 flex flex-col items-center justify-center text-center transform hover:scale-105 transition-transform duration-300">
          <h2 className="text-2xl font-semibold text-teal-300 mb-2">Critical Alerts</h2>
          <p className="text-5xl font-bold text-red-600">
            {alerts.filter(a => a.severity === 'Critical').length}
          </p>
        </div>
        <div className="bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-700 flex flex-col items-center justify-center text-center transform hover:scale-105 transition-transform duration-300">
          <h2 className="2xl font-semibold text-teal-300 mb-2">Daily Traffic Peak</h2>
          <p className="text-5xl font-bold text-green-500">
            {Math.max(...trafficData.datasets[0].data, ...trafficData.datasets[1].data)} MB
          </p>
        </div>
        <div className="bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-700 flex flex-col items-center justify-center text-center transform hover:scale-105 transition-transform duration-300">
          <h2 className="text-2xl font-semibold text-teal-300 mb-2">Threat Types</h2>
          <p className="text-5xl font-bold text-blue-400">
            {threatTypeData.labels.length}
          </p>
        </div>
      </section>

      {/* Charts Section */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-10">
        <div className="bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-700 h-96">
          <Line data={trafficData} options={lineOptions} />
        </div>
        <div className="bg-gray-800 p-6 rounded-lg shadow-lg border border-gray-700 h-96">
          <Bar data={threatTypeData} options={barOptions} />
        </div>
      </section>

      {/* Manual Network Flow Anomaly Prediction Section */}
      <section className="mb-10 p-6 bg-gray-800 rounded-lg shadow-lg border border-gray-700">
        <h2 className="text-3xl font-semibold text-teal-400 mb-6 border-b-2 border-gray-700 pb-3">
          Manual Network Flow Anomaly Prediction
        </h2>
        <p className="text-gray-400 mb-4">
          Use this section to manually test specific network flow JSON data against the model.
        </p>

        <div className="flex gap-4 mb-4">
          <button
            onClick={() => loadExampleFlow('benign')}
            className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-bold rounded-lg shadow-md transition duration-300 ease-in-out transform hover:scale-105"
          >
            Load Example Benign Flow
          </button>
          <button
            onClick={() => loadExampleFlow('attack')}
            className="px-6 py-3 bg-red-600 hover:bg-red-700 text-white font-bold rounded-lg shadow-md transition duration-300 ease-in-out transform hover:scale-105"
          >
            Load Example Attack Flow
          </button>
        </div>

        <textarea
          className="w-full p-4 mb-4 bg-gray-900 border border-gray-700 rounded-lg text-gray-200 resize-y min-h-[200px] font-mono text-sm"
          placeholder="Paste raw network flow JSON here..."
          value={flowInput}
          onChange={(e) => setFlowInput(e.target.value)}
        ></textarea>

        <button
          onClick={() => handlePredict(null)} // Call with null to indicate manual trigger
          disabled={predictionLoading}
          className="w-full py-3 bg-teal-600 hover:bg-teal-700 text-white font-bold rounded-lg shadow-md transition duration-300 ease-in-out transform hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {predictionLoading ? 'Predicting...' : 'Predict Anomaly'}
        </button>

        {predictionError && (
          <div className="mt-4 p-3 bg-red-800 text-red-200 rounded-lg border border-red-700">
            Error: {predictionError}
          </div>
        )}

        {predictionResult && (
          <div className="mt-4 p-4 bg-gray-900 rounded-lg border border-gray-700">
            <h3 className="text-xl font-semibold text-teal-300 mb-2">Prediction Result:</h3>
            <p className="text-lg">
              **Prediction:**{' '}
              <span className={`font-bold ${predictionResult.prediction === 'Anomaly' ? 'text-red-500' : 'text-green-500'}`}>
                {predictionResult.prediction}
              </span>
            </p>
            <p className="text-lg">
              **Anomaly Probability:**{' '}
              <span className="font-bold text-yellow-400">{predictionResult.anomaly_probability}</span>
            </p>
          </div>
        )}
      </section>

      {/* Recent Alerts Section */}
      <section className="mb-10">
        <h2 className="text-3xl font-semibold text-teal-400 mb-6 border-b-2 border-gray-700 pb-3">Recent Alerts</h2>
        <div className="overflow-x-auto">
          <table className="min-w-full bg-gray-800 rounded-lg shadow-lg border border-gray-700">
            <thead>
              <tr className="bg-gray-700 text-left text-gray-300 uppercase text-sm leading-normal">
                <th className="py-3 px-6 rounded-tl-lg">Type</th>
                <th className="py-3 px-6">Severity</th>
                <th className="py-3 px-6">Timestamp</th>
                <th className="py-3 px-6">Source IP</th>
                <th className="py-3 px-6">Destination IP</th>
                <th className="py-3 px-6 rounded-tr-lg">Status</th>
              </tr>
            </thead>
            <tbody className="text-gray-200 text-sm font-light">
              {alerts.slice(0, 5).map((alert, index) => ( // Display only top 5 for brevity
                <tr
                  key={alert.id}
                  className={`border-b border-gray-700 ${index % 2 === 0 ? 'bg-gray-850' : 'bg-gray-800'} hover:bg-gray-700 transition-colors duration-200`}
                >
                  <td className="py-3 px-6">
                    <span
                      className={`py-1 px-3 rounded-full text-xs font-semibold ${
                        alert.type === 'Model Anomaly Detected' || alert.type === 'Malware'
                        ? 'bg-red-900 text-red-300'
                        : alert.type === 'DDoS'
                          ? 'bg-purple-900 text-purple-300'
                          : alert.type === 'Phishing'
                            ? 'bg-yellow-900 text-yellow-300'
                            : alert.type === 'Insider Threat'
                              ? 'bg-blue-900 text-blue-300'
                              : 'bg-green-900 text-green-300' // Default case for other types
                      }`}
                    >
                      {alert.type}
                    </span>
                  </td>
                  <td className="py-3 px-6">
                    <span
                      className={`py-1 px-3 rounded-full text-xs font-semibold ${
                        alert.severity === 'Critical'
                          ? 'bg-red-700 text-red-100'
                          : alert.severity === 'High'
                          ? 'bg-orange-700 text-orange-100'
                          : alert.severity === 'Medium'
                          ? 'bg-yellow-700 text-yellow-100'
                          : 'bg-green-700 text-green-100'
                      }`}
                    >
                      {alert.severity}
                    </span>
                  </td>
                  <td className="py-3 px-6 whitespace-nowrap">
                    {alert.timestamp}
                  </td>
                  <td className="py-3 px-6">{alert.sourceIp}</td>
                  <td className="py-3 px-6">{alert.destinationIp}</td>
                  <td className="py-3 px-6">
                    <span
                      className={`py-1 px-3 rounded-full text-xs font-semibold ${
                        alert.status === 'Active'
                          ? 'bg-red-800 text-red-200'
                          : alert.status === 'Resolved'
                          ? 'bg-green-800 text-green-200'
                          : 'bg-blue-800 text-blue-200'
                      }`}
                    >
                      {alert.status}
                    </span>
                  </td>
                </tr>
              ))}
              {alerts.length === 0 && (
                <tr>
                  <td colSpan="6" className="py-4 px-6 text-center text-gray-400">
                    No recent alerts. Anomalies are detected dynamically.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Footer */}
      <footer className="text-center text-gray-500 text-sm mt-10 pt-6 border-t border-gray-700">
        <p>&copy; {new Date().getFullYear()} Cybersecurity Threat Detection System. All rights reserved.</p>
      </footer>
    </div>
  );
};

export default App;
