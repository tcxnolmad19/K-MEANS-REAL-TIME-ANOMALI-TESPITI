import requests
import random
import time
import os

# Web siteleri ve arama için gerekli parametreler
websites = [
    {
        "name": "Facebook",
        "url": "https://www.facebook.com/search/people/",
        "param": "q"  # Facebook kişi arama parametresi
    },
    {
        "name": "Google",
        "url": "https://www.google.com/search",
        "param": "q"
    },
    {
        "name": "Bing",
        "url": "https://www.bing.com/search",
        "param": "q"
    },
    {
        "name": "DuckDuckGo",
        "url": "https://duckduckgo.com/",
        "param": "q"
    },
    {
        "name": "Yahoo",
        "url": "https://search.yahoo.com/search",
        "param": "p"
    },
    {
        "name": "Wikipedia",
        "url": "https://en.wikipedia.org/w/index.php",
        "param": "search"
    },
    {
        "name": "Amazon",
        "url": "https://www.amazon.com/s",
        "param": "k"
    },
    {
        "name": "Ebay",
        "url": "https://www.ebay.com/sch/i.html",
        "param": "_nkw"
    },
    {
        "name": "Yandex",
        "url": "https://yandex.com/search/",
        "param": "text"
    }
]

# Statik arama terimleri (Facebook dışındaki sitelerde kullanılır)
static_search_terms = [
    # Teknoloji
    "Python programming",
    "Machine learning",
    "Data science",
    "Artificial intelligence",
    "Cybersecurity best practices",
    "Top tech news",
    "Open source tools",
    "How to learn Python",
    "Best IDEs for developers",
    "Quantum computing future",
    "Cloud computing advantages",
    "Blockchain technology explained",
    "IoT applications in daily life",
    "Best coding practices",
    "Top programming languages 2024",
    "AI in healthcare",
    "Cybersecurity certifications",
    "Mobile app development",
    "5G network advantages",
    "How to secure IoT devices",

    # Eğitim
    "Online learning platforms",
    "Top universities in the world",
    "Scholarship opportunities 2024",
    "Best books to read for self-development",
    "How to improve memory",
    "Effective study techniques",
    "Learning new languages",
    "Importance of soft skills",
    "How to ace an interview",
    "Best career choices in 2024",

    # Sağlık
    "Healthy eating habits",
    "Benefits of meditation",
    "How to reduce stress",
    "Exercises for back pain",
    "Yoga for beginners",
    "How to sleep better",
    "Top superfoods for health",
    "Mental health awareness",
    "Symptoms of diabetes",
    "How to boost immunity",

    # Finans
    "How to save money",
    "Best investment strategies 2024",
    "Stock market basics",
    "Cryptocurrency trends",
    "Real estate investment tips",
    "Best credit cards 2024",
    "How to improve credit score",
    "Retirement planning guide",
    "Passive income ideas",
    "How to start a business",

    # Eğlence
    "Top movies to watch 2024",
    "Upcoming video games",
    "Best TV series on Netflix",
    "How to start a podcast",
    "Photography tips for beginners",
    "Best streaming services",
    "Top books to read in 2024",
    "How to play guitar",
    "Travel destinations 2024",
    "Best music albums of the year",

    # Spor
    "Top football players 2024",
    "How to train for a marathon",
    "Best exercises for weight loss",
    "Cricket world cup updates",
    "Fitness tips for beginners",
    "How to improve running speed",
    "Best yoga poses for flexibility",
    "Top sports events 2024",
    "How to start weightlifting",
    "Best cycling routes in the world",

    # Çevre
    "Climate change impact",
    "How to reduce carbon footprint",
    "Best renewable energy sources",
    "Recycling tips for beginners",
    "Sustainable living ideas",
    "Top environmental organizations",
    "How to grow organic vegetables",
    "Global warming effects",
    "How to conserve water",
    "Top green technologies",

    # Genel İlgi
    "Latest COVID-19 updates",
    "How to build self-confidence",
    "Public speaking tips",
    "How to start journaling",
    "Time management techniques",
    "Importance of gratitude",
    "How to set achievable goals",
    "Best productivity apps",
    "How to improve decision-making skills",
    "Mindfulness exercises"
]

# SecLists dosyasından isimleri yükleyen fonksiyon
def load_names_from_seclists(file_path):
    try:
        if not os.path.exists(file_path):
            print(f"SecLists dosyası bulunamadı: {file_path}")
            return []

        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            names = file.read().splitlines()  # Her satırı bir isim olarak oku
        print(f"{len(names)} isim başarıyla yüklendi.")
        return names
    except Exception as e:
        print(f"SecLists dosyası okuma hatası: {e}")
        return []

# Rastgele web sitelerine bağlanıp arama yapan fonksiyon
def search_websites(facebook_names):
    while True:
        # Rastgele bir web sitesi seç
        website = random.choice(websites)

        # Arama terimlerini belirle
        if website["name"] == "Facebook":
            # Facebook için SecLists isimleri kullanılır
            search_term = random.choice(facebook_names)
        else:
            # Diğer siteler için statik arama terimleri kullanılır
            search_term = random.choice(static_search_terms)

        # İstek gönder
        params = {website["param"]: search_term}
        try:
            response = requests.get(website["url"], params=params, timeout=10)
            if response.status_code == 200:
                print(f"{website['name']} üzerinde '{search_term}' araması başarılı!")
            else:
                print(f"{website['name']} üzerinde hata! Durum Kodu: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"{website['name']} bağlantı hatası: {e}")
        
        # Rastgele bekleme süresi (1-2 saniye)
        wait_time = random.uniform(0.1,0.4 )
        print(f"{wait_time:.1f} saniye bekleniyor...\n")
        time.sleep(wait_time)

if __name__ == "__main__":
    # SecLists dosyasının tam yolu
    seclists_path = "/home/selcuk1453/my_project/SecLists/Passwords/Leaked-Databases/rockyou.txt"


    # SecLists dosyasından Facebook için isimleri yükle
    facebook_names = load_names_from_seclists(os.path.expanduser(seclists_path))

    # Facebook için isimler yüklendiyse arama işlemi başlatılır
    if facebook_names:
        print("Arama işlemi başlatılıyor...")
        search_websites(facebook_names)
    else:
        print("Facebook için kullanılacak isimler yüklenemedi. Program sonlandırıldı.")
