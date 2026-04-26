// JADIS — Configuration API

const JADIS_API_URL = 'https://jadis.pages.dev';

const SUPABASE_URL      = 'https://xlvynoqrpquzdnbwzeex.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inhsdnlub3FycHF1emRuYnd6ZWV4Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzcwNDUzODIsImV4cCI6MjA5MjYyMTM4Mn0.ZIkzy-NP_oziszUjR_b67GzfEUevmBHvnjnYM02X9Gc';

const GOOGLE_CLIENT_ID = '';

const ADMIN_EMAILS = ['issamboussalah131@gmail.com', 'shanedarren42@gmail.com'];

function isAdminEmail(email) {
  if (!email) return false;
  return ADMIN_EMAILS.includes(email.toLowerCase().trim());
}
