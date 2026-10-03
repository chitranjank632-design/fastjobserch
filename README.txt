FastJobSerch Render Fix

This version removes better-sqlite3 (native dependency) to avoid Render deployment crashes.
Render: Build = npm install; Start = npm start; Root Directory = blank; Runtime = Node.
Environment: JWT_SECRET (Generate), ADMIN_USER=admin, ADMIN_PASSWORD=your strong password.
Note: data.json is not permanent storage on ephemeral hosting; use managed PostgreSQL for production later.
