# Funkcja, która przyjmuje wektor
def VectorInput(cvss_input):
    # Przyjmowanie ciągu znaków od użytkownika

    # Konwersja wektora CVSSv4 na słownik
    vector = parse_cvss_vector(cvss_input)

    return fullVector(vector) # Przekazanie podzielonego wektora


def parse_cvss_vector(cvss_string):
    vector = {}

    # Usuwamy prefiks "CVSS:4.0/" jeśli istnieje
    if cvss_string.startswith("CVSS:4.0/"):
        cvss_string = cvss_string[9:]

    # Dzielimy ciąg na części według '/'
    parts = cvss_string.split('/')

    # Rozdzielamy każdą część na klucz i wartość
    for part in parts:
        if ":" in part:
            key, value = part.split(':', 1)  # Ograniczamy podział do pierwszego wystąpienia ":"
            vector[key] = value

    return vector


# Funkcja uzupełniająca metryki
def fullVector(vector):
# Słownik ze wszystkimi metrykami o wartośći X
    XVector = {
        "AV": "X",
        "PR": "X",
        "UI": "X",
        "AC": "X",
        "AT": "X",
        "VC": "X",
        "VI": "X",
        "VA": "X",
        "SC": "X",
        "SI": "X",
        "SA": "X",
        "S": "X",
        "AU": "X",
        "R": "X",
        "V": "X",
        "RE": "X",
        "U": "X",
        "MAV": "X",
        "MAC": "X",
        "MAT": "X",
        "MPR": "X",
        "MUI": "X",
        "MVC": "X",
        "MVI": "X",
        "MVA": "X",
        "MSC": "X",
        "MSI": "X",
        "MSA": "X",
        "CR": "X",
        "IR": "X",
        "AR": "X",
        "E": "X"
    }

    # Połączenie 2 słowników
    for key, value in vector.items():
        if key in XVector:
            XVector[key] = value

    # Zmiana na domyślne wartości
    # Jeśli E=X, to domyślnie wartość E to A
    if XVector["E"] == "X":
        XVector["E"] = "A"

    # Jeśli CR=X, to domyślnie wartość CR to H
    if XVector["CR"] == "X":
        XVector["CR"] = "H"

    # Jeśli IR=X, to domyślnie wartość IR to H
    if XVector["IR"] == "X":
        XVector["IR"] = "H"

    # Jeśli AR=X, to domyślnie wartość AR to H
    if XVector["AR"] == "X":
        XVector["AR"] = "H"

    if XVector["AV"] == "X":
        XVector["AV"] = "N"  # Network

    if XVector["AC"] == "X":
        XVector["AC"] = "L"  # Low

    if XVector["AT"] == "X":
        XVector["AT"] = "N"  # None

    if XVector["PR"] == "X":
        XVector["PR"] = "N"  # None

    if XVector["UI"] == "X":
        XVector["UI"] = "N"  # None

    # Uzupełnienie metryk wpływu
    if XVector["VC"] == "X":
        XVector["VC"] = "N"  # None

    if XVector["VI"] == "X":
        XVector["VI"] = "N"  # None

    if XVector["VA"] == "X":
        XVector["VA"] = "N"  # None

    # Uzupełnienie metryk wpływu następczego
    if XVector["SC"] == "X":
        XVector["SC"] = "N"  # None

    if XVector["SI"] == "X":
        XVector["SI"] = "N"  # None

    if XVector["SA"] == "X":
        XVector["SA"] = "N"  # None

    # zastosowanie zmodyfikowanych metryk
    for key in ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA", "S"]:
        modified_key = "M" + key
        if modified_key in XVector and XVector[modified_key] != "X":
            XVector[key] = XVector[modified_key]

    return calculator(XVector) # Przekazanie gotowego wektora do funkcji obliczającej


# Funkcja obliczająca wartość wektora
def calculator(xvector):
    # Jeśli wszystkie metryki wpływu są równe N, nie ma wtedy wpływu
    no_impact_metrics = ['VC', 'VI', 'VA', 'SC', 'SI', 'SA']
    if all(xvector.get(metric) == "N" for metric in no_impact_metrics):
        print("Wszystkie metryki wpływu są równe N - brak wpływu")
        print("Wynik CVSS: 0.0")
        print("Poziom zagrożenia: None")
        return 0.0

    # Obliczenie równoważnych klas dla CVSSv4
    eq = equvalentClasses(xvector)
    print(f"Równoważne klasy (EQ): {eq}")

    # Pobranie bazowego wyniku z tabeli
    base_score = table(eq)
    print(f"Bazowy wynik z tabeli: {base_score}")

    if base_score is None:
        print("Nie znaleziono wartości w tabeli dla tego wektora")
        return None

    # Rozdzielenie wszystkich wartości EQ na zmienne i zmiana na int
    eq1, eq2, eq3, eq4, eq5, eq6 = [int(c) for c in eq]

    # Obliczanie kolejnego niższego makro
    eq1_next_lower_macro = f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}"
    eq2_next_lower_macro = f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}"

    # eq3 i eq6 są połączone - zgodnie z CVSSv4
    if eq3 == 1 and eq6 == 1:
        # 11 --> 21
        eq3eq6_next_lower_macro = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}"
    elif eq3 == 0 and eq6 == 1:
        # 01 --> 11
        eq3eq6_next_lower_macro = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}"
    elif eq3 == 1 and eq6 == 0:
        # 10 --> 11
        eq3eq6_next_lower_macro = f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}"
    elif eq3 == 0 and eq6 == 0:
        # 00 --> 01 lub 00 --> 10
        eq3eq6_next_lower_macro_left = f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}"
        eq3eq6_next_lower_macro_right = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6}"
        has_dual_path = True
    else:
        # 21 --> (nie istnieje w CVSSv4)
        eq3eq6_next_lower_macro = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6 + 1}"

    eq4_next_lower_macro = f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}"
    eq5_next_lower_macro = f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}"

    # Pobieranie score wektorów
    score_eq1_next_lower_macro = table(eq1_next_lower_macro)
    score_eq2_next_lower_macro = table(eq2_next_lower_macro)

    has_dual_path = False
    if eq3 == 0 and eq6 == 0:
        has_dual_path = True
        score_eq3eq6_next_lower_macro_left = table(eq3eq6_next_lower_macro_left)
        score_eq3eq6_next_lower_macro_right = table(eq3eq6_next_lower_macro_right)

        # Wybieramy większą wartość zgodnie z CVSSv4
        if score_eq3eq6_next_lower_macro_left is not None and score_eq3eq6_next_lower_macro_right is not None:
            score_eq3eq6_next_lower_macro = max(score_eq3eq6_next_lower_macro_left, score_eq3eq6_next_lower_macro_right)
        elif score_eq3eq6_next_lower_macro_left is not None:
            score_eq3eq6_next_lower_macro = score_eq3eq6_next_lower_macro_left
        elif score_eq3eq6_next_lower_macro_right is not None:
            score_eq3eq6_next_lower_macro = score_eq3eq6_next_lower_macro_right
        else:
            score_eq3eq6_next_lower_macro = None
    else:
        score_eq3eq6_next_lower_macro = table(eq3eq6_next_lower_macro)

    score_eq4_next_lower_macro = table(eq4_next_lower_macro)
    score_eq5_next_lower_macro = table(eq5_next_lower_macro)

    # Debug info
    print(f"EQ1 next lower: {eq1_next_lower_macro} -> {score_eq1_next_lower_macro}")
    print(f"EQ2 next lower: {eq2_next_lower_macro} -> {score_eq2_next_lower_macro}")
    if has_dual_path:
        print(f"EQ3/EQ6 next lower path 1: {eq3eq6_next_lower_macro_left} -> {score_eq3eq6_next_lower_macro_left}")
        print(f"EQ3/EQ6 next lower path 2: {eq3eq6_next_lower_macro_right} -> {score_eq3eq6_next_lower_macro_right}")
    else:
        print(f"EQ3/EQ6 next lower: {eq3eq6_next_lower_macro} -> {score_eq3eq6_next_lower_macro}")
    print(f"EQ4 next lower: {eq4_next_lower_macro} -> {score_eq4_next_lower_macro}")
    print(f"EQ5 next lower: {eq5_next_lower_macro} -> {score_eq5_next_lower_macro}")

    # Zmiana eq6 na str dla dostępu do słownika
    eq6_str = str(eq6)

    # Lista wektorów o możliwie najwyższym poziomie ryzyka
    try:
        eq_maxes = [
            getMaxSeverityVectorsForEq(eq, 1),
            getMaxSeverityVectorsForEq(eq, 2),
            getMaxSeverityVectorsForEq(eq, 3)[eq6_str],
            getMaxSeverityVectorsForEq(eq, 4),
            getMaxSeverityVectorsForEq(eq, 5)
        ]
    except KeyError as e:
        print(f"Błąd w getMaxSeverityVectorsForEq: {e}")
        print(f"Brakujący klucz w słowniku dla EQ3 lub eq6_str={eq6_str}")
        return None

    max_vectors = []

    # Zagnieżdżona pętla dla wszystkich kombinacji elementów z eq_maxes
    for eq1_max in eq_maxes[0]:
        for eq2_max in eq_maxes[1]:
            for eq3_max in eq_maxes[2]:
                for eq4_max in eq_maxes[3]:
                    for eq5_max in eq_maxes[4]:
                        # Łączenie ciągów w jeden
                        max_vectors.append(eq1_max + eq2_max + eq3_max + eq4_max + eq5_max)

    # Szukanie największego wektora
    max_vector = None
    distances = {}

    print(f"Liczba analizowanych wektorów max: {len(max_vectors)}")

    for m_vector in max_vectors:
        try:
            distances = calculateSeverityDistances(m_vector, xvector)
            if all(distance >= 0 for distance in distances.values()):
                max_vector = m_vector
                print(f"Znaleziono pasujący max_vector: {max_vector}")
                break
        except Exception as e:
            print(f"Błąd podczas przetwarzania wektora {m_vector}: {e}")
            continue

    if max_vector is None:
        print("Nie znaleziono pasującego wektora maksymalnego")
        return None

    # distances zawiera wartości z ostatniego sprawdzanego vectora
    current_severity_distance_eq1 = distances.get("AV", 0) + distances.get("PR", 0) + distances.get("UI", 0)
    current_severity_distance_eq2 = distances.get("AC", 0) + distances.get("AT", 0)
    current_severity_distance_eq3eq6 = (
            distances.get("VC", 0) + distances.get("VI", 0) + distances.get("VA", 0) +
            distances.get("CR", 0) + distances.get("IR", 0) + distances.get("AR", 0)
    )
    current_severity_distance_eq4 = distances.get("SC", 0) + distances.get("SI", 0) + distances.get("SA", 0)

    # Dostępne odległości między poziomami
    available_distance_eq1 = float(base_score) - float(
        score_eq1_next_lower_macro) if score_eq1_next_lower_macro is not None else None
    available_distance_eq2 = float(base_score) - float(
        score_eq2_next_lower_macro) if score_eq2_next_lower_macro is not None else None
    available_distance_eq3eq6 = float(base_score) - float(
        score_eq3eq6_next_lower_macro) if score_eq3eq6_next_lower_macro is not None else None
    available_distance_eq4 = float(base_score) - float(
        score_eq4_next_lower_macro) if score_eq4_next_lower_macro is not None else None
    available_distance_eq5 = float(base_score) - float(
        score_eq5_next_lower_macro) if score_eq5_next_lower_macro is not None else None

    n_existing_lower = 0
    STEP = 0.1

    # Wartości maksymalnych odległości dla EQ - zgodne z CVSSv4
    maxSeverity_eq1 = maxSeverityDistances("eq1", eq1) * STEP
    maxSeverity_eq2 = maxSeverityDistances("eq2", eq2) * STEP
    maxSeverity_eq3eq6 = maxSeverityDistances("eq3eq6", eq3)[eq6] * STEP if eq6 in maxSeverityDistances("eq3eq6",
                                                                                                        eq3) else 0
    maxSeverity_eq4 = maxSeverityDistances("eq4", eq4) * STEP

    print(f"Max severity EQ1: {maxSeverity_eq1}")
    print(f"Max severity EQ2: {maxSeverity_eq2}")
    print(f"Max severity EQ3/EQ6: {maxSeverity_eq3eq6}")
    print(f"Max severity EQ4: {maxSeverity_eq4}")

    # Obliczenia dla eq1
    if available_distance_eq1 is not None:
        n_existing_lower += 1
        percent_to_next_eq1_severity = current_severity_distance_eq1 / maxSeverity_eq1 if maxSeverity_eq1 > 0 else 0
        normalized_severity_eq1 = available_distance_eq1 * percent_to_next_eq1_severity
    else:
        normalized_severity_eq1 = 0

    # Obliczenia dla eq2
    if available_distance_eq2 is not None:
        n_existing_lower += 1
        percent_to_next_eq2_severity = current_severity_distance_eq2 / maxSeverity_eq2 if maxSeverity_eq2 > 0 else 0
        normalized_severity_eq2 = available_distance_eq2 * percent_to_next_eq2_severity
    else:
        normalized_severity_eq2 = 0

    # Obliczenia dla eq3eq6
    if available_distance_eq3eq6 is not None:
        n_existing_lower += 1
        percent_to_next_eq3eq6_severity = current_severity_distance_eq3eq6 / maxSeverity_eq3eq6 if maxSeverity_eq3eq6 > 0 else 0
        normalized_severity_eq3eq6 = available_distance_eq3eq6 * percent_to_next_eq3eq6_severity
    else:
        normalized_severity_eq3eq6 = 0

    # Obliczenia dla eq4
    if available_distance_eq4 is not None:
        n_existing_lower += 1
        percent_to_next_eq4_severity = current_severity_distance_eq4 / maxSeverity_eq4 if maxSeverity_eq4 > 0 else 0
        normalized_severity_eq4 = available_distance_eq4 * percent_to_next_eq4_severity
    else:
        normalized_severity_eq4 = 0

    # Obliczenia dla eq5 (w CVSSv4 zawsze 0)
    if available_distance_eq5 is not None:
        n_existing_lower += 1
        percent_to_next_eq5_severity = 0
        normalized_severity_eq5 = available_distance_eq5 * percent_to_next_eq5_severity
    else:
        normalized_severity_eq5 = 0

    print(f"Normalized EQ1: {normalized_severity_eq1}")
    print(f"Normalized EQ2: {normalized_severity_eq2}")
    print(f"Normalized EQ3/EQ6: {normalized_severity_eq3eq6}")
    print(f"Normalized EQ4: {normalized_severity_eq4}")
    print(f"Normalized EQ5: {normalized_severity_eq5}")

    # Obliczenie średniej odległości
    if n_existing_lower == 0:
        mean_distance = 0
    else:
        mean_distance = (
                                normalized_severity_eq1 + normalized_severity_eq2 +
                                normalized_severity_eq3eq6 + normalized_severity_eq4 +
                                normalized_severity_eq5
                        ) / n_existing_lower

    # Obliczenie wyniku końcowego zgodnie z CVSSv4
    final_score = base_score - mean_distance

    # Ograniczenie wyniku do zakresu 0-10
    final_score = max(0, min(10, final_score))
    final_score = round(final_score, 1)

    print(final_score)

    if final_score == 0:
        print("None")
        score = "None"
    elif final_score < 4.0:
        print("Low")
        score = "Low"
    elif final_score < 7.0:
        print("Medium")
        score = "Medium"
    elif final_score < 9.0:
        print("High")
        score = "High"
    else:
        print("Critical")
        score = "Critical"

    return final_score, score


# Funckja do obliczania rónoważnych klas
def equvalentClasses(vector):
    # EQ1 - dostęp
    AV = vector.get('AV', 'X')
    PR = vector.get('PR', 'X')
    UI = vector.get('UI', 'X')

    EQ1_value = EQ1(AV, PR, UI)

    # EQ2 - złożoność
    AC = vector.get('AC', 'X')
    AT = vector.get('AT', 'X')

    EQ2_value = EQ2(AC, AT)

    # EQ3 - wpływ bezpośredni
    VC = vector.get('VC', 'X')
    VI = vector.get('VI', 'X')
    VA = vector.get('VA', 'X')

    EQ3_value = EQ3(VC, VI, VA)

    # EQ4 - wpływ następczy
    MSI = vector.get('MSI', 'X')
    MSA = vector.get('MSA', 'X')
    SC = vector.get('SC', 'X')
    SI = vector.get('SI', 'X')
    SA = vector.get('SA', 'X')

    EQ4_value = EQ4(MSI, MSA, SC, SI, SA)

    # EQ5 - dojrzałość exploita
    E = vector.get('E', 'X')

    EQ5_value = EQ5(E)

    # EQ6 - wymagania systemowe
    CR = vector.get('CR', 'X')
    IR = vector.get('IR', 'X')
    AR = vector.get('AR', 'X')
    VC = vector.get('VC', 'X')
    VI = vector.get('VI', 'X')
    VA = vector.get('VA', 'X')

    EQ6_value = EQ6(CR, VC, IR, VI, AR, VA)

    value = EQ1_value + EQ2_value + EQ3_value + EQ4_value + EQ5_value + EQ6_value

    return value


def EQ1(AV, PR, UI):
    if AV == "N" and PR == "N" and UI == "N":
        return "0"
    elif (AV == "N" or PR == "N" or UI == "N") and not (AV == "N" and PR == "N" and UI == "N") and AV != "P":
        return "1"
    else:  # AV == "P" lub kombinacja innych wartości
        return "2"


def EQ2(AC, AT):
    if AC == "L" and AT == "N":
        return "0"
    else:
        return "1"


def EQ3(VC, VI, VA):
    if VC == "H" and VI == "H":
        return "0"
    elif not (VC == "H" and VI == "H") and (VC == "H" or VI == "H" or VA == "H"):
        return "1"
    else:  # Żaden wpływ nie jest H
        return "2"


def EQ4(MSI, MSA, SC, SI, SA):
    if MSI == "S" or MSA == "S":
        return "0"
    elif SC == "H" or SI == "H" or SA == "H":
        return "1"
    else:
        return "2"


def EQ5(E):
    if E == "A":
        return "0"
    if E == "P":
        return "1"
    if E == "U":
        return "2"


def EQ6(CR, VC, IR, VI, AR, VA):
    if (CR == "H" and VC == "H") or (IR == "H" and VI == "H") or (AR == "H" and VA == "H"):
        return "0"
    else:
        return "1"


def getMaxSeverityVectorsForEq(macro_vector, eq_number):
    MAX_COMPOSED = {
        # EQ1
        "eq1": {
            0: ["AV:N/PR:N/UI:N/"],
            1: ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
            2: ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"]
        },
        # EQ2
        "eq2": {
            0: ["AC:L/AT:N/"],
            1: ["AC:H/AT:N/", "AC:L/AT:P/"]
        },
        # EQ3 + EQ6
        "eq3": {
            0: {
                "0": ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
                "1": ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"]
            },
            1: {
                "0": ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
                "1": ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
                      "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
                      "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"]
            },
            2: {
                "1": ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]
            }
        },
        # EQ4
        "eq4": {
            0: ["SC:H/SI:S/SA:S/"],
            1: ["SC:H/SI:H/SA:H/"],
            2: ["SC:L/SI:L/SA:L/"]
        },
        # EQ5
        "eq5": {
            0: ["E:A/"],
            1: ["E:P/"],
            2: ["E:U/"]
        }
    }

    return MAX_COMPOSED[f"eq{eq_number}"][int(macro_vector[eq_number - 1])]


def calculateSeverityDistances(max_vector, vector):
    METRIC_LEVELS = {
        "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
        "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
        "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
        "AC": {"L": 0.0, "H": 0.1},
        "AT": {"N": 0.0, "P": 0.1},
        "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
        "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
        "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
        "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
        "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
        "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
        "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
        "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
        "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
        "E": {"U": 0.2, "P": 0.1, "A": 0.0}
    }

    distances = {}

    for metric in METRIC_LEVELS:
        effective_metric_value = vector[metric]

        extracted_metric_value = extractValueMetric(metric, max_vector)

        distances[metric] = METRIC_LEVELS[metric][effective_metric_value] - METRIC_LEVELS[metric][extracted_metric_value]

    return distances


def extractValueMetric(metric, max_Vector):
    # Szuka indeksu początku wartości metryki
    metric_index = max_Vector.find(metric) + len(metric) + 1

    # Wycina wszystko od miejsca, gdzie zaczyna się wartość
    extracted = max_Vector[metric_index:]

    # Jeśli po wartości jest "/", to zwróć tylko to, co przed nim
    if '/' in extracted:
        return extracted.split('/')[0]
    else:
        return extracted


def maxSeverityDistances(eq, number):
    MAX_SEVERITY = {
        "eq1": {
            0: 1,
            1: 4,
            2: 5
        },
        "eq2": {
            0: 1,
            1: 2
        },
        "eq3eq6": {
            0: {0: 7, 1: 6},
            1: {0: 8, 1: 8},
            2: {1: 10}
        },
        "eq4": {
            0: 6,
            1: 5,
            2: 4
        },
        "eq5": {
            0: 1,
            1: 1,
            2: 1
        }
    }

    return MAX_SEVERITY[eq][number]


def table(eq):
    LOOKUP_TABLE = {
        "000000": 10,
        "000001": 9.9,
        "000010": 9.8,
        "000011": 9.5,
        "000020": 9.5,
        "000021": 9.2,
        "000100": 10,
        "000101": 9.6,
        "000110": 9.3,
        "000111": 8.7,
        "000120": 9.1,
        "000121": 8.1,
        "000200": 9.3,
        "000201": 9,
        "000210": 8.9,
        "000211": 8,
        "000220": 8.1,
        "000221": 6.8,
        "001000": 9.8,
        "001001": 9.5,
        "001010": 9.5,
        "001011": 9.2,
        "001020": 9,
        "001021": 8.4,
        "001100": 9.3,
        "001101": 9.2,
        "001110": 8.9,
        "001111": 8.1,
        "001120": 8.1,
        "001121": 6.5,
        "001200": 8.8,
        "001201": 8,
        "001210": 7.8,
        "001211": 7,
        "001220": 6.9,
        "001221": 4.8,
        "002001": 9.2,
        "002011": 8.2,
        "002021": 7.2,
        "002101": 7.9,
        "002111": 6.9,
        "002121": 5,
        "002201": 6.9,
        "002211": 5.5,
        "002221": 2.7,
        "010000": 9.9,
        "010001": 9.7,
        "010010": 9.5,
        "010011": 9.2,
        "010020": 9.2,
        "010021": 8.5,
        "010100": 9.5,
        "010101": 9.1,
        "010110": 9,
        "010111": 8.3,
        "010120": 8.4,
        "010121": 7.1,
        "010200": 9.2,
        "010201": 8.1,
        "010210": 8.2,
        "010211": 7.1,
        "010220": 7.2,
        "010221": 5.3,
        "011000": 9.5,
        "011001": 9.3,
        "011010": 9.2,
        "011011": 8.5,
        "011020": 8.5,
        "011021": 7.3,
        "011100": 9.2,
        "011101": 8.2,
        "011110": 8,
        "011111": 7.2,
        "011120": 7,
        "011121": 5.9,
        "011200": 8.4,
        "011201": 7,
        "011210": 7.1,
        "011211": 5.2,
        "011220": 5,
        "011221": 3,
        "012001": 8.6,
        "012011": 7.5,
        "012021": 5.2,
        "012101": 7.1,
        "012111": 5.2,
        "012121": 2.9,
        "012201": 6.3,
        "012211": 2.9,
        "012221": 1.7,
        "100000": 9.8,
        "100001": 9.5,
        "100010": 9.4,
        "100011": 8.7,
        "100020": 9.1,
        "100021": 8.1,
        "100100": 9.4,
        "100101": 8.9,
        "100110": 8.6,
        "100111": 7.4,
        "100120": 7.7,
        "100121": 6.4,
        "100200": 8.7,
        "100201": 7.5,
        "100210": 7.4,
        "100211": 6.3,
        "100220": 6.3,
        "100221": 4.9,
        "101000": 9.4,
        "101001": 8.9,
        "101010": 8.8,
        "101011": 7.7,
        "101020": 7.6,
        "101021": 6.7,
        "101100": 8.6,
        "101101": 7.6,
        "101110": 7.4,
        "101111": 5.8,
        "101120": 5.9,
        "101121": 5,
        "101200": 7.2,
        "101201": 5.7,
        "101210": 5.7,
        "101211": 5.2,
        "101220": 5.2,
        "101221": 2.5,
        "102001": 8.3,
        "102011": 7,
        "102021": 5.4,
        "102101": 6.5,
        "102111": 5.8,
        "102121": 2.6,
        "102201": 5.3,
        "102211": 2.1,
        "102221": 1.3,
        "110000": 9.5,
        "110001": 9,
        "110010": 8.8,
        "110011": 7.6,
        "110020": 7.6,
        "110021": 7,
        "110100": 9,
        "110101": 7.7,
        "110110": 7.5,
        "110111": 6.2,
        "110120": 6.1,
        "110121": 5.3,
        "110200": 7.7,
        "110201": 6.6,
        "110210": 6.8,
        "110211": 5.9,
        "110220": 5.2,
        "110221": 3,
        "111000": 8.9,
        "111001": 7.8,
        "111010": 7.6,
        "111011": 6.7,
        "111020": 6.2,
        "111021": 5.8,
        "111100": 7.4,
        "111101": 5.9,
        "111110": 5.7,
        "111111": 5.7,
        "111120": 4.7,
        "111121": 2.3,
        "111200": 6.1,
        "111201": 5.2,
        "111210": 5.7,
        "111211": 2.9,
        "111220": 2.4,
        "111221": 1.6,
        "112001": 7.1,
        "112011": 5.9,
        "112021": 3,
        "112101": 5.8,
        "112111": 2.6,
        "112121": 1.5,
        "112201": 2.3,
        "112211": 1.3,
        "112221": 0.6,
        "200000": 9.3,
        "200001": 8.7,
        "200010": 8.6,
        "200011": 7.2,
        "200020": 7.5,
        "200021": 5.8,
        "200100": 8.6,
        "200101": 7.4,
        "200110": 7.4,
        "200111": 6.1,
        "200120": 5.6,
        "200121": 3.4,
        "200200": 7,
        "200201": 5.4,
        "200210": 5.2,
        "200211": 4,
        "200220": 4,
        "200221": 2.2,
        "201000": 8.5,
        "201001": 7.5,
        "201010": 7.4,
        "201011": 5.5,
        "201020": 6.2,
        "201021": 5.1,
        "201100": 7.2,
        "201101": 5.7,
        "201110": 5.5,
        "201111": 4.1,
        "201120": 4.6,
        "201121": 1.9,
        "201200": 5.3,
        "201201": 3.6,
        "201210": 3.4,
        "201211": 1.9,
        "201220": 1.9,
        "201221": 0.8,
        "202001": 6.4,
        "202011": 5.1,
        "202021": 2,
        "202101": 4.7,
        "202111": 2.1,
        "202121": 1.1,
        "202201": 2.4,
        "202211": 0.9,
        "202221": 0.4,
        "210000": 8.8,
        "210001": 7.5,
        "210010": 7.3,
        "210011": 5.3,
        "210020": 6,
        "210021": 5,
        "210100": 7.3,
        "210101": 5.5,
        "210110": 5.9,
        "210111": 4,
        "210120": 4.1,
        "210121": 2,
        "210200": 5.4,
        "210201": 4.3,
        "210210": 4.5,
        "210211": 2.2,
        "210220": 2,
        "210221": 1.1,
        "211000": 7.5,
        "211001": 5.5,
        "211010": 5.8,
        "211011": 4.5,
        "211020": 4,
        "211021": 2.1,
        "211100": 6.1,
        "211101": 5.1,
        "211110": 4.8,
        "211111": 1.8,
        "211120": 2,
        "211121": 0.9,
        "211200": 4.6,
        "211201": 1.8,
        "211210": 1.7,
        "211211": 0.7,
        "211220": 0.8,
        "211221": 0.2,
        "212001": 5.3,
        "212011": 2.4,
        "212021": 1.4,
        "212101": 2.4,
        "212111": 1.2,
        "212121": 0.5,
        "212201": 1,
        "212211": 0.3,
        "212221": 0.1
    }

    if eq in LOOKUP_TABLE:
        return LOOKUP_TABLE[eq]
    else:
        return None
