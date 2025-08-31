Emotion Sense
An AI-powered web application for real-time sentiment and emotion analysis of text and images. Emotion Sense allows users to record their emotional journey through journal entries and image uploads, receiving automated, helpful feedback from an AI.

About the Project
Emotion Sense is a full-stack, secure, and responsive web application designed to help users track their emotional well-being. It leverages powerful AI models to analyze the emotional content of a user's journal entries and uploaded images. The application stores this data and provides a visual representation of mood trends over time using interactive charts.  A core feature is the automatic AI-generated response, which offers supportive and actionable advice tailored to the detected emotion.

You can view a live demo of the application here: https://mgx-mmzvftpvzwc.mgx.world/
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
