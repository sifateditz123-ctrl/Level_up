For BD - Complete UID & Level Dashboard
======================================

এই ZIP-এ যা আছে:
- Admin password দিয়ে Dashboard login
- একাধিক UID যোগ করা
- প্রতিটি অ্যাকাউন্টের Level, নাম, Region ও নোট রাখা
- UID/নাম/Region দিয়ে সার্চ
- অ্যাকাউন্টের তথ্য Edit ও Delete
- CSV Export
- SQLite database
- Render ও Termux চালানোর নির্দেশনা

Render:
1. ZIP Extract করে সব ফাইল GitHub repository-র root-এ upload করুন।
2. Render-এ New > Web Service দিয়ে repository connect করুন।
3. Build Command: pip install -r requirements.txt
4. Start Command: gunicorn server:app
5. Environment Variables:
   SECRET_KEY = দীর্ঘ random secret
   ADMIN_PASSWORD = নিজের শক্তিশালী admin password
   DB_PATH = /var/data/dashboard.db
6. Persistent Disk যোগ করুন, Mount Path: /var/data
7. Deploy করুন।

Termux:
  pkg update && pkg install python -y
  pip install -r requirements.txt
  export ADMIN_PASSWORD='নিজের শক্তিশালী পাসওয়ার্ড'
  export SECRET_KEY='একটি দীর্ঘ random secret'
  python server.py
  তারপর http://127.0.0.1:8000 খুলুন।

গুরুত্বপূর্ণ:
- প্রথমে ADMIN_PASSWORD এবং SECRET_KEY সেট না করলে Login হবে না।
- Render-এ SQLite ডেটা টিকিয়ে রাখতে Persistent Disk আবশ্যক।
- UID ও Level ম্যানুয়ালি যোগ/আপডেট করতে হয়।
- এটি কোনো গেম অ্যাকাউন্টে লগইন করে না; Free Fire session/token সংগ্রহ,
  match automation বা game bot ফিচার অন্তর্ভুক্ত নয়।
- পুরোনো ZIP-এর hardcoded credentials বা tokens নতুন ZIP-এ কপি করা হয়নি।
