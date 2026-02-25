import { initializeApp } from "https://www.gstatic.com/firebasejs/10.7.1/firebase-app.js";

import {
  getAuth,
  GoogleAuthProvider
} from "https://www.gstatic.com/firebasejs/10.7.1/firebase-auth.js";


const firebaseConfig = {
  apiKey: "AIzaSyCzpUhZBVwDhSwkoU7tNN2YeaouQSpeAvg",
  authDomain: "shieldx-c5780.firebaseapp.com",
  projectId: "shieldx-c5780",
  storageBucket: "shieldx-c5780.firebasestorage.app",
  messagingSenderId: "778726971218",
  appId: "1:778726971218:web:bf32c84afd91a7ec6bcc8b",
  measurementId: "G-54TJ9GYHRV"
};



// Initialize
const app = initializeApp(firebaseConfig);


// Auth
const auth = getAuth(app);
const googleProvider = new GoogleAuthProvider();


// Export
export { auth, googleProvider };
