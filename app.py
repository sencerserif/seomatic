import streamlit as st
from google import genai
from google.genai import types
from database import verify_user, init_db # SQLite DB fonksiyonlarını içe aktar

# --- API Anahtarı ve Model Ayarları ---
# Genai istemcisini başlat
try:
    # Google API anahtarını st.secrets veya ortam değişkeninden alır.
    # Gerçek uygulamada st.secrets kullanın.
    client = genai.Client(api_key=st.secrets.get("GEMINI_API_KEY")) 
except Exception:
    client = None
    # Geliştirme ortamında, API anahtarını doğrudan buraya yapıştırabilirsiniz (Tavsiye edilmez!)
    # VEYA, sadece st.error() mesajını bırakarak kullanıcıdan anahtar girmesini isteyebilirsiniz.
    if "GEMINI_API_KEY" not in st.secrets:
        st.error("⚠️ GEMINI_API_KEY bulunamadı! Lütfen Streamlit secrets'a ekleyin.")

# Sistem Talimatları (Identity, Modlar, vb.)
SYSTEM_INSTRUCTIONS = """
SEN SEOMATIC'sin - Google'ın algoritmalarını deşifre eden, rakipleri analiz eden, içerik üreten ve SEO dünyasının tüm kapılarını açan bir AI ajanısın. İçinde 10 farklı uzman kişilik barındırıyorsun ve her biri kendi alanında usta. Kullanıcılarına SEO'da 10 kat üstünlük sağlamak için tasarlandın.

Kurallar:
- Her zaman profesyonel ve yardımsever ol.
- Seçilen moda uygun (icerik, seo, lucifer, killer, vb.) bir uzman gibi davran ve o modun yeteneklerini kullan.
- Black Hat teknikler (Lucifer Modu) istendiğinde MUTLAKA risk uyarısı ver.
- Etik sınırları asla aşma (Lucifer hariç).
- Kullanıcıya somut, uygulanabilir öneriler sun.
- İçerik üretirken SEO en iyi uygulamalarını uygula (H1-H6, anahtar kelime entegrasyonu, okunabilirlik).

Modlar ve Detaylar:
- /mode icerik: Blog, makale, SEO içerik üretimi.
- /mode seo: Anahtar kelime, rakip, teknik SEO analizi.
- /mode rewrite: Mevcut içeriği yeniden yazma, iyileştirme.
- /mode lucifer: Black Hat SEO teknikleri (Çok riskli ve sadece test amaçlı).
- /mode killer: E-ticaret SEO, ürün optimizasyonu.
- /mode humanize: AI içeriğini insansı yapma.
- ... diğer modlar
"""

# --- Uygulama Durum Yönetimi ve Başlangıç Ayarları ---
st.set_page_config(page_title="SEOmatic - Premium SEO Panel", layout="wide")
init_db() # Veritabanını başlat ve varsayılan kullanıcıyı oluştur

if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
if 'current_mode' not in st.session_state:
    st.session_state['current_mode'] = "/mode icerik" # Varsayılan mod
if 'chat_history' not in st.session_state:
    st.session_state['chat_history'] = []

# --- Giriş/Çıkış Fonksiyonları ---

def login_form():
    """Kullanıcı Giriş Formunu gösterir."""
    st.title("🔐 SEOmatic Paneli Giriş")
    with st.form("login_form"):
        st.subheader("Kullanıcı Girişi")
        username = st.text_input("Kullanıcı Adı")
        password = st.text_input("Parola", type="password")
        login_button = st.form_submit_button("Giriş Yap")

        if login_button:
            if verify_user(username, password):
                st.session_state['logged_in'] = True
                st.session_state['username'] = username
                st.rerun() # Sayfayı yenile (Düzeltilmiş)
            else:
                st.error("Kullanıcı adı veya parola hatalı!")
        st.info("Demo Giriş: Kullanıcı Adı: **seomatic**, Parola: **12345**")


def logout():
    """Kullanıcı oturumunu sonlandırır."""
    st.session_state['logged_in'] = False
    st.session_state['current_mode'] = "/mode icerik"
    st.session_state['chat_history'] = []
    st.rerun() # Sayfayı yenile (Düzeltilmiş)

# --- Gemini Çekirdek Fonksiyonu ---

def generate_seo_response(prompt, current_mode):
    """Gemini API'yi çağırır ve yanıtı döner."""
    if client is None:
        return "Gemini API anahtarı ayarlanmadığı için işlem yapılamıyor. Lütfen anahtarınızı ayarlayın."

    full_prompt = f"Aktif Mod: {current_mode}\nKullanıcı İsteği: {prompt}"

    # Streamlit sohbet geçmişini Gemini'nin beklediği formata dönüştür
    history = [
        types.Content(
            role="user" if msg['role'] == 'user' else "model",
            parts=[types.Part.from_text(msg['content'])]
        )
        for msg in st.session_state['chat_history']
    ]
    
    # Yeni mesajı geçmişe ekle
    history.append(types.Content(role="user", parts=[types.Part.from_text(full_prompt)]))

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

    # Üst Bilgi (Header)
    col1, col2 = st.columns([6, 1])
    with col1:
        st.title("🎯 SEOmatic - Premium SEO Agent")
        st.caption(f"Hoş Geldin, **{st.session_state['username']}**! Aktif Mod: **{st.session_state['current_mode']}**")
    with col2:
        st.button("Çıkış Yap", on_click=logout)

    st.markdown("---")

    # Sol Kenar Çubuğu (Mode Seçimi)
    with st.sidebar:
        st.header("⚙️ Uzman Modları")
        
        # Modlar listesi
        modes = {
            "İçerik Yazarı 🖊️": "/mode icerik",
            "SEO Analisti 🔍": "/mode seo",
            "İçerik Yenileyici ♻️": "/mode rewrite",
            "E-ticaret Killer 💰": "/mode killer",
            "AI İnsanlaştırma 🤖": "/mode humanize",
            "Black Hat (Lucifer) 😈": "/mode lucifer"
        }
        
        # Seçim Kutusu
        mode_name = st.selectbox(
            "Aktif Modu Seç:",
            options=list(modes.keys()),
            index=list(modes.values()).index(st.session_state['current_mode'])
        )
        
        # Modu güncelle
        new_mode = modes[mode_name]
        if new_mode != st.session_state['current_mode']:
            st.session_state['current_mode'] = new_mode
            st.session_state['chat_history'] = [] # Mod değişince geçmişi sıfırla
            st.success(f"✅ Mod **{mode_name}** ({new_mode}) olarak ayarlandı. Yeni sohbete başlayabilirsin.")
        
        # Lucifer Modu Uyarısı
        if st.session_state['current_mode'] == "/mode lucifer":
            st.warning("⚠️ **DİKKAT:** Lucifer (Black Hat) modundasınız. Bu teknikler risklidir ve Google cezasına yol açabilir!")
        
        st.markdown("---")
        st.header("📢 Komutlar")
        st.code("/mode [mod_adı] - Mod değiştir", language="markdown")
        st.code("/reset - Sohbeti sıfırla", language="markdown")

    # Ana Sohbet Alanı

    # Geçmişi göster
    for message in st.session_state['chat_history']:
        with st.chat_message(message['role']):
            st.markdown(message['content'])

    # Kullanıcı girişi
    user_prompt = st.chat_input("SEO isteğinizi buraya yazın (Örn: Blog için '2024 SEO Trendleri' makalesi yaz)")

    if user_prompt:
        
        # Komutları kontrol et
        if user_prompt.lower() == "/reset":
            st.session_state['chat_history'] = []
            st.info("Sohbet geçmişi sıfırlandı.")
            st.rerun() # Sayfayı yenile
            return
        
        # Kullanıcı mesajını göster
        with st.chat_message("user"):
            st.markdown(user_prompt)

        # Geçmişe kullanıcı mesajını ekle
        st.session_state['chat_history'].append({"role": "user", "content": user_prompt})

        # Gemini'den yanıt al
        with st.spinner("🤖 SEOmatic düşünülüyor..."):
            response = generate_seo_response(user_prompt, st.session_state['current_mode'])
        
        # Gemini yanıtını göster
        with st.chat_message("assistant"):
            st.markdown(response)

        # Geçmişe Gemini yanıtını ekle
        st.session_state['chat_history'].append({"role": "assistant", "content": response})


# --- Uygulama Başlatma ---

if __name__ == '__main__':
    if st.session_state['logged_in']:
        main_app()
    else:
        login_form()