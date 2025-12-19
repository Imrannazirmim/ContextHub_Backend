# ContestHub - Backend API

This is the backend server for **ContestHub**, a full-featured contest platform that allows creators to host paid contests, users to register via Stripe, submit tasks, and compete for prizes.

The backend is built with **Node.js**, **Express.js**, **MongoDB**, and integrates **Stripe** for payments and **Firebase Admin SDK** for token verification.

### Base URL
🔗 **https://contesthub-server-chi.vercel.app/**  
(Replace with your actual Vercel URL after deployment)

### Tech Stack
- **Node.js** + **Express.js** – RESTful API server
- **MongoDB** (via MongoDB Atlas) – Database for users, contests, payments, submissions, etc.
- **Stripe** – Secure payment processing for contest registration
- **Firebase Admin SDK** – Verify Firebase Authentication tokens for protected routes
- **Vercel** – Serverless deployment

### Environment Variables (.env)
Create a `.env` file in the root directory with the following:

```env
PORT=3000

SITE_DOMAIN=https://your-frontend-domain.netlify.app  # or your live frontend URL

DB_USERNAME=your_mongodb_atlas_username
DB_PASSWORD=your_mongodb_atlas_password

FIREBASE_TOKEN_KEY=your_firebase_service_account_json_encoded_in_base64
```
