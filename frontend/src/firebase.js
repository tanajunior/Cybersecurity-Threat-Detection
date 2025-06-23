// src/firebase.js

import { initializeApp } from "firebase/app";
import { getAuth, signInAnonymously } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

const firebaseConfig = {
  apiKey: "AIzaSyDcEBOOctKNY368AGyrasHS3LCD0IjCvDw",
  authDomain: "tidal-digit-462908-n9.firebaseapp.com",
  databaseURL: "https://tidal-digit-462908-n9-default-rtdb.firebaseio.com",
  projectId: "tidal-digit-462908-n9",
  storageBucket: "tidal-digit-462908-n9.firebasestorage.app",
  messagingSenderId: "413007343348",
  appId: "1:413007343348:web:32a76f7f4c8750d16ab8a1",
};


const app = initializeApp(firebaseConfig);
export const db = getFirestore(app);
export const auth = getAuth(app);

// Optional auto-login
signInAnonymously(auth).catch((error) => {
  console.error("Anonymous sign-in failed:", error);
});
