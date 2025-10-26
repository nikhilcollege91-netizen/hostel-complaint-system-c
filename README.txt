Hostel Complaint System (C) - Render-ready

1. Place your `templates/` and `static/` folders here (same HTML/CSS/JS as Python project).
2. Ensure Dockerfile and server.c are in repo root.
3. On Render: Create a Web Service pointing at this repo. Add environment variable: PORT=10000
4. Deploy. Logs should show "Server running on port 10000".
5. Default warden: hostelwarden.cu@gmail.com / CUWARDEN
6. Upload endpoint: POST /upload with raw binary body and header X-FILENAME: filename.ext (max 5MB)
7. API endpoints:
   - POST /api/register (name,email,password,room optional)
   - POST /api/login (email,password) -> returns token
   - GET /api/complaints (Authorization: <token>)
   - POST /api/complaint (Authorization: <token>) (title,type,description,filename)
   - POST /api/complaint/update (Authorization: <token>) (warden only) (id,status)
   - GET /api/analytics (Authorization: <token>) (warden only)
