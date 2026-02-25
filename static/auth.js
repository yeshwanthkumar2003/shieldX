// ================= IMPORTS =================

// Import from your firebase config
import { auth, googleProvider } from "./firebase.js";

// Import Firebase Auth functions from CDN
import {
  signInWithPopup,
  signOut
} from "https://www.gstatic.com/firebasejs/10.7.1/firebase-auth.js";


// 🔥 FORCE GOOGLE ACCOUNT CHOOSER EVERY TIME
googleProvider.setCustomParameters({
  prompt: "select_account"
});


// ================= PASSWORD TOGGLE =================

window.togglePassword = function () {

  const input = document.getElementById("password");

  input.type = input.type === "password" ? "text" : "password";

};



// ================= NORMAL LOGIN =================

window.loginUser = async function (e) {

  e.preventDefault();

  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  const remember = document.getElementById("remember")?.checked || false;

  const error = document.getElementById("error");
  error.innerText = "";

  try {

    const res = await fetch("/login", {

      method: "POST",

      headers: {
        "Content-Type": "application/json"
      },

      body: JSON.stringify({
        username,
        password,
        remember
      })

    });

    const data = await res.json();

    if (!data.success) {

      error.innerText = data.message || "Login failed";
      return;

    }

    // Email verification check
    if (!data.verified) {

      error.innerText = "Please verify your email first.";
      return;

    }

    // Success
    window.location.href = "/drive";

  }

  catch (err) {

    console.error(err);
    error.innerText = "Server error. Try again.";

  }

};



// ================= GOOGLE LOGIN =================

window.loginWithGoogle = async function () {

  const error = document.getElementById("error");
  error.innerText = "";

  try {

    // 🔥 Clear previous Firebase session
    await signOut(auth);

    // 🔥 Open Google popup with account chooser
    const result = await signInWithPopup(auth, googleProvider);

    // Get ID Token
    const token = await result.user.getIdToken();

    // Send token to Flask backend
    const res = await fetch("/google-login", {

      method: "POST",

      headers: {
        "Content-Type": "application/json"
      },

      body: JSON.stringify({
        token: token
      })

    });

    const data = await res.json();

    if (!data.success) {

      error.innerText = "Google login failed";
      return;

    }

    // Success → redirect to drive
    window.location.href = "/drive";

  }

  catch (err) {

    console.error("Google Login Error:", err);
    error.innerText = err.message || "Google authentication failed";

  }

};



// ================= SIGNUP =================

window.signupUser = async function (e) {

  e.preventDefault();

  const name = document.getElementById("name").value;
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  const confirm = document.getElementById("confirm").value;
  const terms = document.getElementById("terms").checked;

  const error = document.getElementById("error");
  const success = document.getElementById("success");

  error.innerText = "";
  success.innerText = "";

  if (password.length < 8) {
    error.innerText = "Password must be at least 8 characters";
    return;
  }

  if (password !== confirm) {
    error.innerText = "Passwords do not match";
    return;
  }

  if (!terms) {
    error.innerText = "Accept terms to continue";
    return;
  }

  try {

    const res = await fetch("/signup", {

      method: "POST",

      headers: {
        "Content-Type": "application/json"
      },

      body: JSON.stringify({
        name,
        email,
        password
      })

    });

    const data = await res.json();

    if (!data.success) {
      error.innerText = data.message;
      return;
    }

    success.innerText = "Account created! Check email.";

    setTimeout(() => {
      window.location.href = "/";
    }, 1500);

  }

  catch (err) {

    error.innerText = "Signup failed";

  }

};



// ================= PASSWORD STRENGTH =================

window.checkStrength = function (pwd) {

  let score = 0;

  if (pwd.length >= 8) score++;
  if (/[a-z]/.test(pwd)) score++;
  if (/[A-Z]/.test(pwd)) score++;
  if (/[0-9]/.test(pwd)) score++;
  if (/[^A-Za-z0-9]/.test(pwd)) score++;

  const labels = ["", "Weak", "Fair", "Good", "Strong", "Very Strong"];
  const colors = ["", "#ff4444", "#ff8800", "#ffbb33", "#00C851", "#007E33"];

  const fill = document.getElementById("strengthFill");
  const text = document.getElementById("strengthText");

  if (fill) {
    fill.style.width = (score / 5) * 100 + "%";
    fill.style.background = colors[score];
  }

  if (text) {
    text.innerText = labels[score];
    text.style.color = colors[score];
  }

};