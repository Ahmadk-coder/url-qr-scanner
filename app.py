import os
import re
from flask import Flask, render_template, request, jsonify
from PIL import Image
from pyzbar.pyzbar import decode

app = Flask(__name__)

def analyze_url(url):
    reasons = []
    is_suspicious = False
    
    if not url.startswith("https://"):
        reasons.append("الموقع لا يستخدم بروتوكول التشفير الآمن (HTTPS). / The site does not use HTTPS.")
        is_suspicious = True

    if len(url) > 75:
        reasons.append("عنوان الرابط طويل جداً بشكل غير معتاد. / The URL is unusually long.")
        is_suspicious = True

    phishing_keywords = ['login', 'verify', 'account', 'update', 'banking', 'secure', 'signin', 'paypal', 'free']
    found_keywords = [word for word in phishing_keywords if word in url.lower()]
    if found_keywords:
        reasons.append(f"الرابط يحتوي على كلمات مشبوهة: ({', '.join(found_keywords)}). / Contains suspicious keywords.")
        is_suspicious = True

    ip_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.match(ip_pattern, url):
        reasons.append("الرابط يستخدم عنوان IP مباشر بدلاً من اسم نطاق. / Uses a direct IP address.")
        is_suspicious = True

    if is_suspicious:
        status = "مشبوه / مرتفع الخطورة (Suspicious / High Risk)"
        message = "تم العثور على مؤشرات قد تشير إلى خطورة هذا الرابط. يُرجى توخي الحذر."
    else:
        status = "منخفض الخطورة / يبدو آمناً (Low Risk / Looks Safe)"
        message = "لم يتم العثور على أنماط تصيد معروفة في هيكل الرابط. ينصح دائماً بالحذر."

    return {
        "status": status,
        "message": message,
        "reasons": reasons,
        "url": url
    }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/scan-url', methods=['POST'])
def scan_url():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "يرجى إدخال رابط صحيح"}), 400
    return jsonify(analyze_url(url))

@app.route('/api/scan-qr', methods=['POST'])
def scan_qr():
    if 'qr_image' not in request.files:
        return jsonify({"error": "لم يتم تقديم صورة الـ QR"}), 400
    file = request.files['qr_image']
    if file.filename == '':
        return jsonify({"error": "لم يتم اختيار ملف"}), 400
    try:
        image = Image.open(file)
        decoded_objects = decode(image)
        if not decoded_objects:
            return jsonify({"error": "تعذر التعرف على رمز QR في الصورة المرفوعة"}), 400
        extracted_url = decoded_objects[0].data.decode('utf-8')
        return jsonify(analyze_url(extracted_url))
    except Exception as e:
        return jsonify({"error": f"حدث خطأ أثناء معالجة الصورة: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)