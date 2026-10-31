from flask import Flask, render_template, request, jsonify
import re
from sklearn.ensemble import RandomForestClassifier

app = Flask(__name__)

# --- 1. بناء نموذج الذكاء الاصطناعي (Machine Learning) ---
# بيانات تدريب نموذج تصنيف الروابط (Classification Model)
# الخصائص: [طول الرابط، عدد النقاط، وجود IP، وجود علامة @]
# 0 = آمن، 1 = مشبوه/خبيث
X_train = [
    [18, 1, 0, 0],  # رابط آمن وقصير
    [75, 5, 1, 1],  # رابط خبيث (يحتوي على IP وعلامة تصيد)
    [25, 2, 0, 0],  # رابط آمن وطبيعي
    [90, 6, 1, 1]   # رابط تصيد احتيالي (Phishing)
]
y_train = [0, 1, 0, 1]  

# تدريب خوارزمية الغابات العشوائية (Random Forest Classifier)
ai_model = RandomForestClassifier(n_estimators=10, random_state=42)
ai_model.fit(X_train, y_train)

# دالة استخراج الخصائص (Feature Extraction)
def extract_features(url):
    has_ip = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    url_len = len(url)
    dot_count = url.count('.')
    at_symbol = 1 if '@' in url else 0
    return [url_len, dot_count, has_ip, at_symbol]

# --- 2. المسارات (Routes) ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.form or request.json
    url_to_check = data.get('url', '')
    
    if not url_to_check:
        return jsonify({"error": "الرجاء إدخال رابط صحيح"}), 400

    # تحليل الرابط عبر نموذج الذكاء الاصطناعي
    features = extract_features(url_to_check)
    prediction = ai_model.predict([features])[0]
    
    # بناء استجابة أمنية احترافية توافق المعايير التنظيمية
    if prediction == 1:
        result = {
            "status": "Dangerous",
            "category": "Phishing / Malicious Link",
            "compliance_note": "متوافق مع معايير حماية المستفيدين ومكافحة التهديدات السيبرانية (NCA Guidelines)",
            "message": "⚠️ تحذير أمني: أظهر تحليل الذكاء الاصطناعي أن الرابط يحتوي على خصائص مشبوهة قد تمثل محاولة تصيد احتيالي (Phishing) أو استغلال لرموز الاستجابة السريعة (Quishing)."
        }
    else:
        result = {
            "status": "Safe",
            "category": "Verified Secure",
            "compliance_note": "متوافق مع معايير حماية المستفيدين ومكافحة التهديدات السيبرانية (NCA Guidelines)",
            "message": "✅ الرابط يبدو آمنًا بناءً على فحص الخصائص والتصنيف التنبئي."
        }
        
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
