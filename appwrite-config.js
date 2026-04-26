// ═══════════════════════════════════════════════════════════════
//  JADIS — Configuration Appwrite
//
//  SETUP (une seule fois dans la console Appwrite) :
//  1. Crée un projet sur https://cloud.appwrite.io
//  2. Remplace APPWRITE_PROJECT_ID ci-dessous
//  3. Crée une Database (ID : "jadis-db")
//  4. Crée ces 5 collections avec les attributs indiqués :
//
//  Collection "users"
//    uid (string 36), name (string 128), email (string 128),
//    lastLogin (string 32), registeredAt (string 32),
//    miroir (string 10000), associations (string 10000),
//    associations_updated (string 32)
//
//  Collection "subscribers"
//    email (string 128), addedAt (string 32), addedBy (string 64)
//
//  Collection "loginEvents"
//    uid (string 36), name (string 128), email (string 128),
//    event (string 32), timestamp (string 32), userAgent (string 256)
//
//  Collection "pageViews"
//    page (string 128), timestamp (string 32), sessionId (string 64),
//    referrer (string 256), userAgent (string 256)
//
//  Collection "community"
//    posts (string 50000), updated (string 32)
//
//  5. Pour chaque collection : Permissions → Any → Read + Write
//     (tu pourras verrouiller plus tard avec des rôles Appwrite)
// ═══════════════════════════════════════════════════════════════

const APPWRITE_ENDPOINT   = 'https://cloud.appwrite.io/v1';
const APPWRITE_PROJECT_ID = 'VOTRE_PROJECT_ID'; // ← remplace par ton Project ID
const APPWRITE_DB_ID      = 'jadis-db';          // ← doit correspondre à l'ID créé dans la console

// ── Admins ───────────────────────────────────────────────────
const ADMIN_EMAILS = ["issamboussalah131@gmail.com", "shanedarren42@gmail.com"];

function isAdminEmail(email) {
  if (!email) return false;
  return ADMIN_EMAILS.includes(email.toLowerCase().trim());
}

// ── Convertit un email en ID de document valide pour Appwrite ─
// Appwrite n'accepte que a-z A-Z 0-9 _ - (max 36 chars)
function emailToDocId(email) {
  return email.toLowerCase()
    .replace(/@/g, '_')
    .replace(/\./g, '-')
    .replace(/[^a-zA-Z0-9_-]/g, '_')
    .substring(0, 36);
}
