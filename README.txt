📘 كيفية تشغيل المشروع

1️⃣ انسخي الملف .env.example
2️⃣ غيري اسمه إلى .env
3️⃣ ضعي مفاتيحك في الأماكن المناسبة، مثل:

GSB_API_KEY=YOUR_GOOGLE_SAFE_BROWSING_KEY
URLSCAN_API_KEY=YOUR_URLSCAN_KEY
OPENAI_API_KEY=YOUR_OPENAI_KEY


4️⃣ شغّلي المشروع بالأوامر التالية:

.venv\Scripts\activate
python -m uvicorn main:app --reload
