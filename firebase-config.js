// ═══════════════════════════════════════════════════════════════
//  JADIS — Configuration Firebase
//  → Va sur https://console.firebase.google.com
//  → Crée un projet → Paramètres du projet → Tes applications
//  → Copie les valeurs ci-dessous
// ═══════════════════════════════════════════════════════════════
const FIREBASE_CONFIG = {
  apiKey: "AIzaSyD3W_DQZxFJqAV9dhNfEM4loUXLqjBZYZQ",
  authDomain: "jadis-c1d9c.firebaseapp.com",
  projectId: "jadis-c1d9c",
  storageBucket: "jadis-c1d9c.firebasestorage.app",
  messagingSenderId: "298518204571",
  appId: "1:298518204571:web:49ed654aa639da01daf63e",
  measurementId: "G-KR0DE1KGJ3"
};

// Emails admin — accès complet automatique sur tout le site
const ADMIN_EMAIL  = "issamboussalah131@gmail.com"; // admin principal (rétro-compat)
const ADMIN_EMAILS = ["issamboussalah131@gmail.com", "shanedarren42@gmail.com"];

// Helper : vrai si l'email fourni est un admin
function isAdminEmail(email) {
  if (!email) return false;
  return ADMIN_EMAILS.includes(email.toLowerCase().trim());
}
