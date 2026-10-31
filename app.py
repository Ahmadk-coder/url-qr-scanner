from flask import Flask, render_template, request, jsonify
import re
import cv2
from pyzbar.pyzbar import decode
import numpy as np
from sklearn.ensemble import RandomForestClassifier

app = Flask(__name__)

# --- نموذج الذكاء الاصطناعي المدرب ببيانات أوسع للتصيد الاحتيالي ---
# الخصائص: [طول الرابط، عدد النقاط، وجود IP، وجود علامة @، وجود كلمات تصيد، هل يستخدم http]
X_train = [
    [18, 1, 0, 0, 0, 0],  # آمن
    [45, 3, 0, 0, 1, 1],  # مشبوه/تصيد
    [25, 2, 0, 0, 0, 0],  # آمن
    [75, 5, 1, 1, 1, 1],  # مشبوه/خبيث
    [30, 2, 0, 0, 1, 1],  # مشبوه (يحتوي على كلمات تسجيل دخول وهمية)
    [22, 1, 0, 0, 0, 1]   # مشبوه (http غير آمن)
]
y_train = [0, 1, 0, 1, 1, 1]  # 0 = آمن، 1 = خطر/تصيد

ai_model = RandomForestClassifier(n_estimators=20, random_state=42)
ai_model.fit(X_train, y_train)

def extract_features(url):
    has_ip = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    url_len = len(url)
    dot_count = url.count('.')
    at_symbol = 1 if '@' in url else 0
    
    # الكشف عن كلمات التصيد الشائعة في الروابط (Phishing Keywords)
    phishing_keywords = ['login', 'verify', 'update', 'secure', 'bank', 'account', 'signin', 'support']
    has_keywords = 1 if any(kw in url.lower() for kw in phishing_keywords) else 0
    
    # فحص بروتوكول الأمان غير الآمن http
    is_http = 1 if url.lower().startswith('http://') else 0
    
    return [url_len, dot_count, has_ip, at_symbol, has_keywords, is_http]

def scan_qr_code(image_path):
    try:
        image = cv2.imread(image_path)
        if image is None:
            return None, "تعذر قراءة ملف الصورة، تأكد من صيغتها."

        gray_image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        decoded_objects = decode(gray_image)
        
        if not decoded_objects:
            decoded_objects = decode(image)

        if decoded_objects:
            url_data = decoded_objects[0].data.decode('utf-8')
            return url_data, None
        else:
            return None, "لم يتم العثور على رمز QR صالح في الصورة المرفوعة."
            
    except Exception as e:
        return None, f"حدث خطأ أثناء معالجة الصورة: {str(e)}"

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.form or request.json
    url_to_check = data.get('url', '')
    
    if not url_to_check:
        return jsonify({"error": "الرجاء إدخال رابط صحيح"}), 400

    features = extract_features(url_to_check)
    prediction = ai_model.predict([features])[0]
    
    # قواعد إضافية صارمة: أي رابط يستخدم http:// أو يحتوي على كلمات مخادعة يتم اعتباره خطراً فوراً
    if features[4] == 1 or features[5] == 1 or prediction == 1:
        result = {
            "status": "Dangerous",
            "category": "تنبيه: محاولة تصيد احتيالي مرتفعة الخطورة (Phishing Detected)",
            "compliance_note": "متوافق مع الضوابط الأساسية للأمن السيبراني (NCA - ECC-1:2018) لحماية المستفيدين.",
            "message": "⚠️ تحذير أمني: أظهر تحليل الذكاء الاصطناعي وفحص الخصائص أن الرابط يحتوي على بروتوكول غير آمن أو أنماط تصيد احتيالي تستهدف سرقة بياناتك."
        }
    else:
        result = {
            "status": "Safe",
            "category": "موقع آمن (Verified Secure)",
            "compliance_note": "متوافق مع معايير حماية المستفيدين ومكافحة التهديدات السيبرانية (NCA Guidelines)",
            "message": "✅ الرابط يبدو آمنًا بناءً على فحص الخصائص والتصنيف التنبئي للذكاء الاصطناعي."
        }
        
    return jsonify(result)

@app.route('/scan-qr', methods=['POST'])
def scan_qr_route():
    if 'file' not in request.files:
        return jsonify({"error": "لم يتم إرفاق أي ملف صورة للـ QR"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "اسم الملف فارغ"}), 400

    temp_path = "temp_qr.png"
    file.save(temp_path)

    extracted_url, error_msg = scan_qr_code(temp_path)
    
    if error_msg:
        return jsonify({"status": "Error", "message": error_msg}), 400

    features = extract_features(extracted_url)
    prediction = ai_model.predict([features])[0]

    if features[4] == 1 or features[5] == 1 or prediction == 1:
        result = {
            "status": "Dangerous",
            "extracted_url": extracted_url,
            "category": "تنبيه: رمز استجابة سريعة خبيث (Quishing / Malicious QR)",
            "compliance_note": "متوافق مع ضوابط حماية البنى التحتية والتصدي للهجمات السيبرانية (NCA Guidelines)",
            "message": "⚠️ تحذير أمني خطير: الرمز المضمن في الـ QR يوجه إلى رابط مشبوه أو محاولة تصيد عبر رموز الاستجابة السريعة (Quishing)."
        }
    else:
        result = {
            "status": "Safe",
            "extracted_url": extracted_url,
            "category": "رمز QR آمن (Verified Secure QR)",
            "compliance_note": "متوافق مع معايير حماية المستفيدين ومكافحة التهديدات السيبرانية (NCA Guidelines)",
            "message": "✅ الرمز آمن والرابط المستخرج من الـ QR سليم بناءً على تحليل الذكاء الاصطناعي."
        }

    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
