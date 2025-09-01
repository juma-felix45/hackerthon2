COMAND PROMPT FED TO AI

I want you to help me design and implement a complete full-stack web application called "EMOTION SENSE”. The project should be AI-enabled Interactive, secure, and responsive. Help me develop this website and also a preview of it.
Tech Stack
- Frontend: HTML5, CSS3, JavaScript (with Chart.js for mood trends, responsive design)
- Backend: Python Flask (single file or modular with Blueprints for scalability)
- Database: MySQL
- AI: Hugging Face Sentiment Analysis API (text emotion analysis) + basic image emotion analysis (face/emotion recognition via AI model or API)
- Security: JWT authentication, password hashing (Werkzeug), rate limiting, input sanitization
- Deployment: Flask dev server locally; optionally Gunicorn + Nginx for production
 Key Requirements
1. User Authentication & Authorization
   - Registration form (mandatory fields: name, age, location, phone number, ID number, marital status, email, password).
   - Login/logout system.
   - JWT-based authentication (sessions not allowed).
   - Role-based access: normal users vs. admins.
   - only allow one user with e-mail drjameskamau91@gmail.com
   - Provide an option for a person who forgot an email to retrieve/reset the password 
For the support, let an individual contact  
2. Frontend
   - `index.html` with:
     - Login/register forms.
     - Journal entry form (hidden until login).
     - File upload for profile picture and emotion image capture (via webcam and upload).
     - Comments section to describe the emotion end to be responded by AI (only logged-in users).
     - About Us & Contact section.
      -hungging face question 
     - Admin-only panel link.
   - Responsive, attractive design with background colors red, green, blue, yellow.
   - Use `styles.css` for styling, `app.js` for logic (fetch API calls to Flask backend).
   - Hide/show forms depending on authentication state.
3. Backend (Flask in `app.py`)
   - `/api/register` → Register new users.
   - approval of registered users
   - `/api/login` → Returns JWT token.
   - `/api/entries` → Accepts journal entry + optional image, calls Hugging Face API for sentiment/emotion, stores result in DB.
   - `/api/comments` → Allows logged-in users to leave comments.
   - `/api/admin/users` → Admin-only route to view all users.
only allow user with e-mail drjameskamau91@gmail.com to be admin
provide a otp verification code number to an email/sms to the number registered to allow logging in
   - Secure password storage (Werkzeug).
   - Hugging Face API integration with bearer token.
4. Automated AI Response (Key Feature)
   - After emotion is detected (via text or image):
     - The system should generate detailed automatic AI response providing recomendation based on the mood.
     - Examples:
       - Happy → “Keep sharing your positivity with others!”
       - Sad → “We recommend reaching out to a counselor. Here’s a list of contacts.”
       - Stressed → “Try breathing exercises or taking a walk. If persistent, consult a professional.”
       - Angry → “Pause, reflect, and practice mindfulness. You may also reach out to a therapist.”
   - AI responses should always be stored in Database along with the journal entry and displayed back to the user.
   - Include hospital/counselor recommendations if emotions indicate need for professional help.
5. Database Schema
   - `users`: id, name, age, location, phone, id_number, marital_status, email, password_hash, role, created_at.
   - `journal_entries`: id, user_id, text, image_path, emotion_result, ai_response, created_at.
   - `comments`: id, user_id, comment, created_at.
6. Security
   - Input sanitization using `bleach`.
   - JWT token verification middleware.
   - File upload restrictions: only PNG/JPG/JPEG under 5MB.
   - Rate limiting login attempts.
   - Admin-only routes fully protected.
7. Features
   - Text emotion analysis via Hugging Face API.
   - Image upload + optional webcam capture for emotions.
   - Chart.js frontend visualization for mood trends.
   - AI-generated recommendations automatically given after each analysis.
   - Contact section + comment section for feedback.
   - Admin can view users & moderate content.
Admin can view and store the user passwords
8. File Structure
emotion_sense/
├─ templates/
│   └─ index.html
├─ static/
│   ├─ styles.css
│   └─ app.js
├─ uploads/
├─ app.py
├─ requirements.txt
└─ schema.sql
Deliverables
- `index.html` → full frontend page with login, register, forms, webcam, and sections.
- `styles.css` → responsive, modern styling with square image previews.
- `app.js` → handles login/register/logout state, hides/shows forms, fetch calls to Flask backend, updates Chart.js visualizations.
- `app.py` → secure Flask backend with routes, JWT, Hugging Face integration, MySQL connection, image handling, and automatic AI response generation.
- `schema.sql` → database schema with users, journal_entries, comments (including `role` field for admins and `ai_response` for entries).
- `requirements.txt` → dependencies list.
- Instructions to run project locally:
1. Install dependencies `pip install -r requirements.txt`
2. Configure MySQL credentials in `app.py`
3. Add Hugging Face API key in `app.py`
4. Run with `python app.py`
Your task: generate, refine, and improve the entire project step by step with all files included.


Emotion Sense
An AI-powered web application for real-time sentiment and emotion analysis of text and images. Emotion Sense allows users to record their emotional journey through journal entries and image uploads, receiving automated, helpful feedback from an AI.

About the Project
Emotion Sense is a full-stack, secure, and responsive web application designed to help users track their emotional well-being. It leverages powerful AI models to analyze the emotional content of a user's journal entries and uploaded images. The application stores this data and provides a visual representation of mood trends over time using interactive charts.  A core feature is the automatic AI-generated response, which offers supportive and actionable advice tailored to the detected emotion.

You can view a live demo of the application here: https://mgx-mmzvftpvzwc.mgx.world/
https://mgx-mmzvftpvzwc.mgx.world/
You can view a pitch deck: https://gamma.app/docs/Emotion-Sense-Unlocking-Emotional-Well-being-with-AI-hytjo30pq6s30eu

Features
AI-Powered Emotion Analysis: Analyzes user-submitted text and images for sentiment and emotion.

User Authentication: Secure user registration, login, and logout using JWT authentication.

Journaling & Image Upload: Users can create journal entries and upload images to reflect on their feelings.

Automated AI Responses: Generates instant, automated AI responses with guidance and recommendations based on the user's emotional state.

Mood Trends Visualization: Visualizes a user's mood history with interactive charts powered by Chart.js.

Admin Panel: An exclusive section for administrators to manage users and monitor content.

Secure & Responsive: The application is built with robust security measures and a responsive design for a seamless user experience across devices.

Tech Stack
Frontend:

HTML5, CSS3, JavaScript (for a responsive, modern design and dynamic behavior)

Chart.js (for data visualization)

Backend:

Python Flask (for the server-side logic and API endpoints)

MySQL (as the relational database)

AI & Security:

Hugging Face Sentiment Analysis API (for text-based emotion detection)

AI Model/API for Image Recognition (for image-based emotion detection)

JWT (for token-based authentication)

Werkzeug (for password hashing)

Bleach (for input sanitization)

Deployment:

Flask Dev Server (for local development)

Gunicorn + Nginx (for production deployment)

Key Requirements
User Authentication & Authorization: Implements secure registration and login, with distinct roles for normal users and administrators. Sessions are not used; all authentication is JWT-based.

Frontend Design: Features a responsive design with a dynamic interface that shows/hides forms based on the user's authentication status. Includes forms for registration, login, journal entries, and a comments section.

Backend Routes: Provides secure API endpoints for user management (/api/register, /api/login, /api/admin/users) and content processing (/api/entries, /api/comments).

Automated AI Responses: A key feature where the backend, upon analyzing emotion, automatically generates and stores an AI response, which is then displayed back to the user.

Database Schema: A structured MySQL database with tables for users, journal_entries, and comments to store all necessary data.

Security Measures: Ensures a secure application by implementing input sanitization, rate limiting, and robust JWT token verification.



