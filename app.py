import streamlit as st
from google import genai
from google.genai import types
from database import verify_user, init_db, add_user 
import os

# --- API Anahtarı ve Model Ayarları ---
try:
    # Gemini API anahtarını Streamlit secrets'tan okur
    api_key = st.secrets.get("GEMINI_API_KEY")
    if not api_key:
        # Eğer secrets'ta yoksa ortam değişkenine bak (Local/VPS için)
        api_key = os.getenv("GEMINI_API_KEY")
    
    if api_key:
        client = genai.Client(api_key=api_key)
    else:
        client = None
        st.error("⚠️ GEMINI_API_KEY bulunamadı! Lütfen Streamlit secrets'a ekleyin.")

except Exception as e:
    client = None
    st.error(f"⚠️ İstemci başlatma hatası: {e}")

# --- Sistem Talimatları ---
SYSTEM_INSTRUCTIONS = """
SEN SEOMATIC'sin - Google'ın algoritmalarını deşifre eden, rakipleri analiz eden, içerik üreten ve SEO dünyasının tüm kapılarını açan bir AI ajanısın. İçinde 10 farklı uzman kişilik barındırıyorsun. Kullanıcılarına SEO'da 10 kat üstünlük sağlamak için tasarlandın.

Kurallar:
- Her zaman profesyonel ve yardımsever ol.
- Seçilen moda uygun (icerik, seo, lucifer, killer, vb.) bir uzman gibi davran.
- Black Hat teknikler (Lucifer Modu) istendiğinde MUTLAKA risk uyarısı ver.
- Etik sınırları asla aşma (Lucifer hariç).
- Kullanıcıya somut, uygulanabilir öneriler sun.
"""

# --- Uygulama Durum Yönetimi ve Başlangıç Ayarları ---
st.set_page_config(page_title="SEOmatic - Premium SEO Panel", layout="wide")
init_db() 

if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
if 'current_mode' not in st.session_state:
    st.session_state['current_mode'] = "/mode icerik" 
if 'chat_history' not in st.session_state:
    st.session_state['chat_history'] = []
if 'username' not in st.session_state:
    st.session_state['username'] = None

# --- Giriş/Kayıt/Çıkış Fonksiyonları ---

def login_form():
    """Kullanıcı Giriş Formunu gösterir."""
    with st.form("login_form"):
        st.subheader("Giriş Yap")
        username = st.text_input("Kullanıcı Adı")
        password = st.text_input("Parola", type="password")
        login_button = st.form_submit_button("Giriş Yap")

        if login_button:
            if verify_user(username, password):
                st.session_state['logged_in'] = True
                st.session_state['username'] = username
                st.rerun() 
            else:
                st.error("Kullanıcı adı veya parola hatalı!")
        st.info("Demo Giriş: Kullanıcı Adı: **seomatic**, Parola: **12345**")

def register_form():
    """Kullanıcı Kayıt Formunu gösterir."""
    with st.form("register_form"):
        st.subheader("Yeni Hesap Oluştur")
        new_username = st.text_input("Yeni Kullanıcı Adı")
        new_password = st.text_input("Parola (Min 6 Karakter)", type="password")
        register_button = st.form_submit_button("Hesap Oluştur")

        if register_button:
            if len(new_username) < 4 or len(new_password) < 6:
                st.error("Kullanıcı adı en az 4, parola en az 6 karakter olmalıdır.")
            else:
                success = add_user(new_username, new_password)
                if success:
                    st.success("✅ Hesap başarıyla oluşturuldu! Şimdi **Giriş Yap** sekmesini kullanabilirsiniz.")
                else:
                    st.error("Bu kullanıcı adı zaten kullanılıyor. Lütfen başka bir ad seçin.")

def logout():
    """Kullanıcı oturumunu sonlandırır."""
    st.session_state['logged_in'] = False
    st.session_state['current_mode'] = "/mode icerik"
    st.session_state['chat_history'] = []
    st.session_state['username'] = None
    st.rerun()

# --- Gemini Çekirdek Fonksiyonu (DÜZELTİLDİ) ---

def generate_seo_response(prompt, current_mode):
    """Gemini API'yi çağırır ve yanıtı döner."""
    if client is None:
        return "Gemini API anahtarı ayarlanmadığı için işlem yapılamıyor."

    # Prompt'u string olduğundan emin olarak oluştur
    full_prompt = str(f"Aktif Mod: {current_mode}\nKullanıcı İsteği: {prompt}")

    history = []
    
    # Geçmiş mesajları işle
    for msg in st.session_state['chat_history']:
        try:
            content_txt = msg.get('content')
            if not content_txt:
                continue
            
            # İçeriği zorla string yap
            safe_content = str(content_txt)

            # types.Part.from_text kullanırken 'text=' parametresini açıkça belirt
            history.append(
                types.Content(
                    role="user" if msg['role'] == 'user' else "model",
                    parts=[types.Part.from_text(text=safe_content)]
                )
            )
        except Exception:
            continue
        
    # Yeni mesajı ekle (BURASI HATAYI ÇÖZEN KISIM)
    try:
        history.append(
            types.Content(
                role="user", 
                parts=[types.Part.from_text(text=full_prompt)] # 'text=' eklendi
            )
        )
    except Exception as e:
        return f"Mesaj oluşturma hatası: {e}"

    try:
        response = client.models.generate_content(
            model='gemini-2.5-pro',
            contents=history,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTIONS,
                temperature=0.7 
            )
        )
        return response.text
    except Exception as e:
        return f"Gemini API Hatası: {e}"


# --- Ana Panel Arayüzü ---

def main_app():
    """Ana SEO Panelini gösterir."""

    col1, col2 = st.columns([6, 1])
    with col1:
        st.title("🎯 SEOmatic - Premium SEO Agent")
        st.caption(f"Hoş Geldin, **{st.session_state['username']}**! Aktif Mod: **{st.session_state['current_mode']}**")
    with col2:
        st.button("Çıkış Yap", on_click=logout)

    st.markdown("---")

    with st.sidebar:
        st.header("⚙️ Uzman Modları")
        
        modes = {
            "İçerik Yazarı 🖊️": "/mode icerik",
            "SEO Analisti 🔍": "/mode seo",
            "İçerik Yenileyici ♻️": "/mode rewrite",
            "E-ticaret Killer 💰": "/mode killer",
            "AI İnsanlaştırma 🤖": "/mode humanize",
            "Black Hat (Lucifer) 😈": "/mode lucifer"
        }
        
        mode_name = st.selectbox(
            "Aktif Modu Seç:",
            options=list(modes.keys()),
            index=list(modes.values()).index(st.session_state['current_mode'])
        )
        
        new_mode = modes[mode_name]
        if new_mode != st.session_state['current_mode']:
            st.session_state['current_mode'] = new_mode
            st.session_state['chat_history'] = [] 
            st.success(f"✅ Mod **{mode_name}** ({new_mode}) olarak ayarlandı.")
            st.rerun()
        
        if st.session_state['current_mode'] == "/mode lucifer":
            st.warning("⚠️ **DİKKAT:** Lucifer (Black Hat) modundasınız.")
        
        st.markdown("---")
        
        if st.button("🗑️ SOHBETİ SIFIRLA (Hata Çözümü)"):
            st.session_state['chat_history'] = []
            st.success("Sohbet geçmişi temizlendi!")
            st.rerun()

    # Sohbet Geçmişini Göster
    for message in st.session_state['chat_history']:
        content = message.get('content')
        if content:
            with st.chat_message(message['role']):
                st.markdown(str(content))

    user_prompt = st.chat_input("SEO isteğinizi buraya yazın...")

    if user_prompt:
        if user_prompt.lower() == "/reset":
            st.session_state['chat_history'] = []
            st.rerun() 
            return
        
        with st.chat_message("user"):
            st.markdown(user_prompt)

        st.session_state['chat_history'].append({"role": "user", "content": user_prompt})

        with st.spinner("🤖 SEOmatic düşünülüyor..."):
            response = generate_seo_response(user_prompt, st.session_state['current_mode'])
        
        with st.chat_message("assistant"):
            st.markdown(response)

        st.session_state['chat_history'].append({"role": "assistant", "content": response})


# --- Uygulama Başlatma ---

if __name__ == '__main__':
    if st.session_state['logged_in']:
        main_app()
    else:
        st.title("🔐 SEOmatic Premium SEO Paneli")
        tab1, tab2 = st.tabs(["🔐 Giriş Yap", "✍️ Kayıt Ol"])
        with tab1:
            login_form()
        with tab2:
            register_form()
