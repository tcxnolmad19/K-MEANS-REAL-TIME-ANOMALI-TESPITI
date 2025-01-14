import requests
import random
import time

# Web siteleri ve arama için gerekli parametreler
websites = [
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

# Arama terimleri
search_terms = [
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

# Web sitelerine bağlanıp arama yapma
def search_websites():
    while True:
        # Rastgele bir web sitesi ve arama terimi seç
        website = random.choice(websites)
        search_term = random.choice(search_terms)

        # İstek gönder
        params = {website["param"]: search_term}  # Arama parametresini ekle
        try:
            response = requests.get(website["url"], params=params, timeout=10)
            if response.status_code == 200:
                print(f"{website['name']} üzerinde '{search_term}' araması başarılı!")
            else:
                print(f"{website['name']} üzerinde hata! Durum Kodu: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"{website['name']} bağlantı hatası: {e}")
        
        # Rastgele bekleme süresi (5-15 saniye)
        wait_time = random.randint(0,1 )
        print(f"{wait_time} saniye bekleniyor...\n")
        time.sleep(wait_time)

if __name__ == "__main__":
    search_websites()
