import os
import time
import requests
import streamlit as st

st.set_page_config(page_title="SmartShield", page_icon="🛡️", layout="centered")

VT_BASE = "https://www.virustotal.com/api/v3"

def get_api_key():
    # Recommended: set VT_API_KEY in Streamlit Cloud Secrets.
    try:
        secret_value = st.secrets.get("VT_API_KEY", "")
        if secret_value:
            return str(secret_value).strip()
    except Exception:
        pass
    return os.getenv("VT_API_KEY", "").strip()

def normalize_url(value):
    value = value.strip()
    if not value:
        return ""
    if not value.lower().startswith(("http://", "https://")):
        value = "https://" + value
    return value

def submit_url(url, api_key):
    response = requests.post(
        f"{VT_BASE}/urls",
        headers={"x-apikey": api_key},
        data={"url": url},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["data"]["id"]

def get_analysis(analysis_id, api_key):
    response = requests.get(
        f"{VT_BASE}/analyses/{analysis_id}",
        headers={"x-apikey": api_key},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["data"]["attributes"]

def scan_url(url, api_key):
    analysis_id = submit_url(url, api_key)
    # VirusTotal analysis is asynchronous; wait briefly for the result.
    progress = st.progress(0, text="Submitting URL to VirusTotal…")
    for attempt in range(12):
        attributes = get_analysis(analysis_id, api_key)
        stats = attributes.get("stats", {})
        status = attributes.get("status", "")
        progress.progress(min((attempt + 1) / 12, 1.0),
                          text="Waiting for scan results…")
        if status == "completed" or stats:
            progress.empty()
            return attributes
        time.sleep(2)
    progress.empty()
    return get_analysis(analysis_id, api_key)

language = st.selectbox("Language / اللغة", ["العربية", "English"])

if language == "العربية":
    st.title("🛡️ SmartShield")
    st.write("نظام فحص الروابط المشبوهة باستخدام VirusTotal.")
    prompt = "أدخلي الرابط الذي تريدين فحصه:"
    button_text = "افحص الرابط"
    empty_message = "الرجاء إدخال رابط أولاً."
    missing_key = "مفتاح VirusTotal API غير مضبوط بعد. أضيفيه في إعدادات Secrets في Streamlit Cloud باسم VT_API_KEY."
    invalid_url = "الرابط غير صالح. تأكدي من كتابته بشكل صحيح."
    result_title = "نتيجة الفحص"
    malicious_label = "اكتشافات خبيثة"
    suspicious_label = "اكتشافات مشبوهة"
    harmless_label = "مصادر صنّفته سليماً"
    undetected_label = "لم تكتشفه المصادر"
    timeout_message = "أُرسل الرابط للفحص، لكن النتيجة لم تكتمل بعد. حاولي مرة أخرى بعد قليل."
    disclaimer = "تنبيه: لا تفتحي الروابط المشبوهة. نتائج الفحص ليست ضماناً كاملاً للسلامة. استخدام VirusTotal API المجاني يخضع لشروطه وحدوده."
    error_prefix = "تعذّر إكمال الفحص:"
else:
    st.title("🛡️ SmartShield")
    st.write("Scan suspicious URLs using VirusTotal.")
    prompt = "Enter the URL you want to check:"
    button_text = "Scan URL"
    empty_message = "Please enter a URL first."
    missing_key = "VirusTotal API key is not configured. Add it in Streamlit Cloud Secrets as VT_API_KEY."
    invalid_url = "That URL does not look valid. Please check it and try again."
    result_title = "Scan results"
    malicious_label = "Malicious detections"
    suspicious_label = "Suspicious detections"
    harmless_label = "Harmless verdicts"
    undetected_label = "Undetected"
    timeout_message = "The URL was submitted, but the analysis is not complete yet. Try again shortly."
    disclaimer = "Do not open suspicious links. Scan results cannot guarantee safety. The free VirusTotal API is subject to its terms and quotas."
    error_prefix = "Could not complete the scan:"

st.divider()
with st.form("url_scan_form"):
    url_input = st.text_input(prompt, placeholder="https://example.com")
    submitted = st.form_submit_button(button_text, use_container_width=True)

if submitted:
    if not url_input.strip():
        st.warning(empty_message)
    else:
        url = normalize_url(url_input)
        api_key = get_api_key()
        if not api_key:
            st.error(missing_key)
        else:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                if parsed.scheme not in ("http", "https") or not parsed.hostname or "." not in parsed.hostname:
                    st.error(invalid_url)
                else:
                    with st.spinner("VirusTotal is checking the URL…" if language == "English" else "جاري فحص الرابط عبر VirusTotal…"):
                        attributes = scan_url(url, api_key)
                    stats = attributes.get("stats", {})
                    malicious = int(stats.get("malicious", 0))
                    suspicious = int(stats.get("suspicious", 0))
                    harmless = int(stats.get("harmless", 0))
                    undetected = int(stats.get("undetected", 0))
                    st.subheader(result_title)
                    c1, c2 = st.columns(2)
                    c1.metric(malicious_label, malicious)
                    c2.metric(suspicious_label, suspicious)
                    c3, c4 = st.columns(2)
                    c3.metric(harmless_label, harmless)
                    c4.metric(undetected_label, undetected)

                    if malicious > 0:
                        st.error("⚠️ " + ("VirusTotal found malicious detections." if language == "English" else "تم العثور على اكتشافات خبيثة لهذا الرابط."))
                    elif suspicious > 0:
                        st.warning("⚠️ " + ("Some engines marked this URL as suspicious." if language == "English" else "بعض محركات الفحص صنّفت الرابط كمشبوه."))
                    elif attributes.get("status") != "completed":
                        st.info(timeout_message)
                    else:
                        st.success("No malicious or suspicious detections were reported in this analysis." if language == "English" else "لم تظهر اكتشافات خبيثة أو مشبوهة في نتيجة هذا الفحص.")
                    st.caption("Analysis status: " + str(attributes.get("status", "unknown")))
                    st.caption(disclaimer)
            except requests.HTTPError as exc:
                code = exc.response.status_code if exc.response is not None else "unknown"
                if code == 401:
                    detail = "API key rejected. Check the VT_API_KEY secret." if language == "English" else "مفتاح API غير مقبول. تحققي من قيمة VT_API_KEY في Secrets."
                elif code == 429:
                    detail = "VirusTotal rate/quota limit reached. Try later." if language == "English" else "وصلتِ إلى حد الطلبات المسموح من VirusTotal. حاولي لاحقاً."
                else:
                    detail = f"VirusTotal returned HTTP {code}."
                st.error(f"{error_prefix} {detail}")
            except requests.RequestException:
                st.error(error_prefix + ("Network or VirusTotal connection problem." if language == "English" else "مشكلة اتصال بالشبكة أو بخدمة VirusTotal."))
            except (KeyError, ValueError, TypeError):
                st.error(error_prefix + ("Unexpected response from VirusTotal." if language == "English" else "وصل رد غير متوقع من VirusTotal."))

st.divider()
st.caption("SmartShield — Browse safely, stay protected.")
