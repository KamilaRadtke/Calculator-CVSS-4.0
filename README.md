# CVSS Calculator 4.0

## Opis projektu

CVSS Calculator 4.0 to aplikacja webowa służąca do obliczania wyników CVSS (Common Vulnerability Scoring System) w wersji 4.0. Projekt umożliwia użytkownikom wprowadzanie wektorów CVSS, które są następnie przetwarzane i analizowane w celu obliczenia wyniku oraz poziomu zagrożenia.

## Struktura projektu

Projekt składa się z następujących komponentów:

### Frontend
- `index.html`: Strona główna aplikacji z formularzem do wprowadzania metryk CVSS
- `Static/script.js`: Logika JavaScript obsługująca interakcję użytkownika z formularzem oraz komunikację z backendem
- `Static/style.css`: Stylizacja aplikacji

### Backend
- `app.py`: Główna aplikacja Flask obsługująca żądania HTTP i komunikację między frontendem a backendem
- `cvss.py`: Logika obliczania wyników CVSS na podstawie wprowadzonych wektorów

### Inne pliki
- `main.py`: Skrypt testowy do lokalnego uruchamiania funkcji obliczeniowych
- `.idea/`: Folder konfiguracyjny dla IDE

## Jak działa aplikacja?

### Frontend

1. Użytkownik wprowadza metryki CVSS w formularzu na stronie głównej
2. Po kliknięciu przycisku "Pokaż wektor", aplikacja generuje wektor CVSS na podstawie wprowadzonych danych i wyświetla go na stronie
3. Po kliknięciu przycisku "Wyślij i oblicz wynik", aplikacja wysyła wektor CVSS do backendu w celu obliczenia wyniku

### Backend

#### `app.py`
- Obsługuje żądania HTTP
- Funkcja `/calculate` przyjmuje wektor CVSS, przetwarza go za pomocą funkcji `VectorInput` z pliku `cvss.py`, a następnie zwraca wynik i poziom zagrożenia

#### `cvss.py`
- Funkcja `VectorInput` przetwarza wektor CVSS, konwertując go na słownik
- Funkcja `fullVector` uzupełnia brakujące metryki domyślnymi wartościami zgodnie z dokumentacją CVSS 4.0
- Funkcja `calculator` oblicza wynik CVSS na podstawie równoważnych klas metryk (EQ) oraz tabeli wyników
- Funkcje pomocnicze, takie jak `equvalentClasses`, `table`, i `calculateSeverityDistances`, wspierają proces obliczeń

### Wynik

Backend zwraca wynik CVSS (liczbowy) oraz poziom zagrożenia (np. "Low", "Medium", "High", "Critical"), które są wyświetlane na stronie.

## Jak uruchomić projekt?

### Wymagania

- Python 3.12 lub nowszy
- Flask
- Przeglądarka internetowa

### Instrukcja

1. Zainstaluj wymagane zależności:
   ```bash
   pip install flask
   ```

2. Uruchom aplikację:
   ```bash
   python app.py
   ```

3. Otwórz przeglądarkę i przejdź do `http://127.0.0.1:5000`

## Testowanie lokalne

Do testowania funkcji obliczeniowych możesz użyć skryptu `main.py`, który pozwala na wprowadzanie wektorów CVSS w konsoli.

## Dokumentacja CVSS 4.0

Aplikacja opiera się na specyfikacji CVSS 4.0, która definiuje metryki i sposób obliczania wyników. Szczegółowe informacje na temat metryk i ich wartości można znaleźć na stronie [FIRST.org](https://www.first.org/cvss/).

## Przykładowy wektor CVSS

**Wektor:** `CVSS:4.0/AV:N/PR:N/UI:N/AC:L/VC:H/VI:H/VA:H`

- **AV** (Attack Vector): Network (N)
- **PR** (Privileges Required): None (N)
- **UI** (User Interaction): None (N)
- **AC** (Attack Complexity): Low (L)
- **VC** (Confidentiality Impact): High (H)
- **VI** (Integrity Impact): High (H)
- **VA** (Availability Impact): High (H)

**Wynik:** 9.3 (Critical)

