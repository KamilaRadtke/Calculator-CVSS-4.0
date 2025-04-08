# Funkcja, która przyjmuje wektor
def VectorInput():
    # Przyjmowanie ciągu znaków od użytkownika
    cvss_input = input("Podaj CVSS: ")

    # Tworzymy słownik, w którym klucze
    vector = {}

    # Dzielimy ciąg na części według '/'
    parts = cvss_input.split('/')

    # Rozdzielamy każdą część na klucz i wartość
    for part in parts:
        key, value = part.split(':')
        vector[key] = value

    fullVector(vector) # Przekazanie podzielonego wektora

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

    for key, value in XVector.items():
        modificated_metric = "M" + str(key)
        if modificated_metric in XVector and not XVector[modificated_metric] == "X":
            XVector[key] = XVector[modificated_metric]

    calculator(XVector) # Przekazanie gotowego wektora do funkcji obliczającej


# Funkcja obliczająca wartość wektora
def calculator(xvector):
    # Jeśli te metryki są równe N, nie ma wtedy wpływu
    no_impact_metrics = ['VC', 'VI', 'VA', 'SC', 'SI', 'SA']
    if all(xvector.get(metric) == "N" for metric in no_impact_metrics):
        print(0)
        return 0.0

    eq = equvalentClasses(xvector) # Obliczone wartośći równoważnych klas jako jeden string
    print(f"obliczona wartość równoważnych klas {eq}")

    value = table(eq) # Score wektora
    print(f"score wektora {value}")

    # Rozdzielenie wszystkich wartośći EQ na zmienne i zmiana na int
    eq1, eq2, eq3, eq4, eq5, eq6 = [int(c) for c in eq]

    # Obliczanie kolejego niższewgo makro
    eq1_next_lower_macro = f"{eq1 + 1}{eq2}{eq3}{eq4}{eq5}{eq6}"
    eq2_next_lower_macro = f"{eq1}{eq2 + 1}{eq3}{eq4}{eq5}{eq6}"

    # eq3 i eq6 są połączone
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
    # 00 --> 01
    # 00 --> 10
        eq3eq6_next_lower_macro_left = f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6 + 1}"
        eq3eq6_next_lower_macro_right = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}${eq6}"
    else:
    # 21 --> 32 (nie istnieje)
        eq3eq6_next_lower_macro = f"{eq1}{eq2}{eq3 + 1}{eq4}{eq5}{eq6 + 1}"

    eq4_next_lower_macro = f"{eq1}{eq2}{eq3}{eq4 + 1}{eq5}{eq6}"
    eq5_next_lower_macro = f"{eq1}{eq2}{eq3}{eq4}{eq5 + 1}{eq6}"

    # Pobieranie score wektorów
    score_eq1_next_lower_macro = table(eq1_next_lower_macro)
    score_eq2_next_lower_macro = table(eq2_next_lower_macro)

    if eq3 == 0 and eq6 == 0:
        score_eq3eq6_next_lower_macro_left = table(eq3eq6_next_lower_macro_left)
        score_eq3eq6_next_lower_macro_right = table(eq3eq6_next_lower_macro_right)

        score_eq3eq6_next_lower_macro = max(score_eq3eq6_next_lower_macro_left, score_eq3eq6_next_lower_macro_right);

    else:
        score_eq3eq6_next_lower_macro = table(eq3eq6_next_lower_macro)

    score_eq4_next_lower_macro = table(eq4_next_lower_macro)
    score_eq5_next_lower_macro = table(eq5_next_lower_macro)

    # Zmiana eq6 na str
    eq6_str = str(eq6)

    # Lista wektorów o możliwie najwyższym poziomie ryzyka
    eq_maxes = [
        getMaxSeverityVectorsForEq(eq, 1),
        getMaxSeverityVectorsForEq(eq, 2),
        getMaxSeverityVectorsForEq(eq, 3)[eq6_str],
        getMaxSeverityVectorsForEq(eq, 4),
        getMaxSeverityVectorsForEq(eq, 5)
    ]

    print(f'wybrane maksymalne {eq_maxes}')

    max_vectors = []

    # Zagnieżdżona pętla dla wszystkich kombinacji elementów z eq_maxes
    for eq1_max in eq_maxes[0]:
        for eq2_max in eq_maxes[1]:
            for eq3_max in eq_maxes[2]:
                for eq4_max in eq_maxes[3]:
                    for eq5_max in eq_maxes[4]:
                        # Łączenie ciągów w jeden
                        max_vectors.append(eq1_max + eq2_max + eq3_max + eq4_max + eq5_max)

    print('max wektory czyli kombinacje')
    for vector in max_vectors:
        print(vector)

    # Szukanie największego wektora
    max_vector = None
    distances = {}

    for m_vector in max_vectors:
        distances = calculateSeverityDistances(m_vector, xvector)

        print(f"dystans {distances}")

        if all(distance >= 0 for distance in distances.values()):
            max_vector = m_vector
            break

    print(f"powinen byc cały słownik dystansów {distances}")
    print(f"obliczony max wektor {max_vector}")

    # distances zawiera wartości z ostatniego sprawdzanego vectora
    current_severity_distance_eq1 = distances["AV"] + distances["PR"] + distances["UI"]
    current_severity_distance_eq2 = distances["AC"] + distances["AT"]
    current_severity_distance_eq3eq6 = distances["VC"] + distances["VI"] + distances["VA"] + distances["CR"] + distances["IR"] + distances["AR"]
    current_severity_distance_eq4 = distances["SC"] + distances["SI"] + distances["SA"]

    print(f"obliczone dystanse {current_severity_distance_eq1}, {current_severity_distance_eq2},{current_severity_distance_eq3eq6}, {current_severity_distance_eq4}")

    if score_eq1_next_lower_macro is not None:
        available_distance_eq1 = float(value) - float(score_eq1_next_lower_macro)
    else:
        available_distance_eq1 = None

    if score_eq2_next_lower_macro is not None:
        available_distance_eq2 = float(value) - float(score_eq2_next_lower_macro)
    else:
        available_distance_eq2 = None

    if score_eq3eq6_next_lower_macro is not None:
        available_distance_eq3eq6 = float(value) - float(score_eq3eq6_next_lower_macro)
    else:
        available_distance_eq3eq6 = None

    if score_eq4_next_lower_macro is not None:
        available_distance_eq4 = float(value) - float(score_eq4_next_lower_macro)
    else:
        available_distance_eq4 = None

    if score_eq5_next_lower_macro is not None:
        available_distance_eq5 = float(value) - float(score_eq5_next_lower_macro)
    else:
        available_distance_eq5 = None

    print(f"dostepne dystanse czyli od value odejmujemy {available_distance_eq1}, {available_distance_eq2}, {available_distance_eq3eq6}, available_distance_eq4, {available_distance_eq5}")

    percent_to_next_eq1_severity = 0
    percent_to_next_eq2_severity = 0
    percent_to_next_eq3eq6_severity = 0
    percent_to_next_eq4_severity = 0
    percent_to_next_eq5_severity = 0

    n_existing_lower = 0

    normalized_severity_eq1 = 0
    normalized_severity_eq2 = 0
    normalized_severity_eq3eq6 = 0
    normalized_severity_eq4 = 0
    normalized_severity_eq5 = 0

    STEP = 0.1

    maxSeverity_eq1 = maxSeverityDistances("eq1", eq1) * STEP
    maxSeverity_eq2 = maxSeverityDistances("eq2", eq2) * STEP
    maxSeverity_eq3eq6 = maxSeverityDistances("eq3eq6", eq3)[eq6] * STEP
    maxSeverity_eq4 = maxSeverityDistances("eq4", eq4) * STEP


    # Obliczenia dla eq1
    if available_distance_eq1 is not None:  # Sprawdzanie, czy dostępny dystans jest liczbą
        n_existing_lower += 1
        percent_to_next_eq1_severity = current_severity_distance_eq1 / maxSeverity_eq1
        normalized_severity_eq1 = available_distance_eq1 * percent_to_next_eq1_severity
    else:
        print("else1")
        normalized_severity_eq1 = 0

    # Obliczenia dla eq2
    if available_distance_eq2 is not None:
        n_existing_lower += 1
        percent_to_next_eq2_severity = current_severity_distance_eq2 / maxSeverity_eq2
        normalized_severity_eq2 = available_distance_eq2 * percent_to_next_eq2_severity
    else:
        print("else2")
        normalized_severity_eq2 = 0

    # Obliczenia dla eq3eq6
    if available_distance_eq3eq6 is not None:
        n_existing_lower += 1
        percent_to_next_eq3eq6_severity = current_severity_distance_eq3eq6 / maxSeverity_eq3eq6
        normalized_severity_eq3eq6 = available_distance_eq3eq6 * percent_to_next_eq3eq6_severity
    else:
        print("else3")
        normalized_severity_eq3eq6 = 0

    # Obliczenia dla eq4
    if available_distance_eq4 is not None:
        n_existing_lower += 1
        percent_to_next_eq4_severity = current_severity_distance_eq4 / maxSeverity_eq4
        normalized_severity_eq4 = available_distance_eq4 * percent_to_next_eq4_severity
    else:
        print("else4")
        normalized_severity_eq4 = 0

    # Obliczenia dla eq5 (czyli zawsze 0)
    if available_distance_eq5 is not None:
        n_existing_lower += 1
        percent_to_next_eq5_severity = 0
        normalized_severity_eq5 = available_distance_eq5 * percent_to_next_eq5_severity
    else:
        print("else5")
        normalized_severity_eq5 = 0

    print(normalized_severity_eq1,normalized_severity_eq2, normalized_severity_eq3eq6, normalized_severity_eq4, normalized_severity_eq5)

    if n_existing_lower == 0:
        mean_distance = 0
    else:
        mean_distance = (normalized_severity_eq1 + normalized_severity_eq2 + normalized_severity_eq3eq6 + normalized_severity_eq4 + normalized_severity_eq5) / n_existing_lower

    # Obliczenie wyniku końcowego
    final_score = value - mean_distance

    # Ograniczenie wyniku do zakresu 0-10
    final_score = max(0, min(10, final_score))

    final_score = round(final_score, 1)

    print(final_score)


# Funckja do obliczania rónoważnych klas
def equvalentClasses(vector):
    # EQ1
    AV = vector['AV']
    PR = vector['PR']
    UI = vector['UI']

    EQ1_value = EQ1(AV, PR, UI)

    # EQ2
    AC = vector['AC']
    AT = vector['AT']

    EQ2_value = EQ2(AC, AT)

    # EQ3
    VC = vector['VC']
    VI = vector['VI']
    VA = vector['VA']

    EQ3_value = EQ3(VC, VI, VA)

    # EQ4
    MSI = vector['MSI']
    MSA = vector['MSA']
    SI = vector['SI']
    SC = vector['SC']
    SA = vector['SA']

    EQ4_value = EQ4(MSI, MSA, SC, SI, SA)

    # EQ5
    E = vector['E']

    EQ5_value = EQ5(E)

    #EQ6
    CR = vector['CR']
    IR = vector['IR']
    AR = vector['AR']
    VC = vector['VC']
    VI = vector['VI']
    VA = vector['VA']

    EQ6_value = EQ6(CR, VC, IR, VI, AR, VA)

    print(EQ1_value, EQ2_value, EQ3_value, EQ4_value, EQ5_value, EQ6_value)

    value = EQ1_value + EQ2_value + EQ3_value + EQ4_value + EQ5_value + EQ6_value

    return value


def EQ1(AV, PR, UI):
    if (AV == "N" and PR == "N" and UI == "N"):
        return "0"
    elif (AV == "N" or PR == "N" or UI == "N") and not (AV == "N" and PR == "N" and UI == "N") and AV != "P":
        return "1"
    elif (AV == "P") and not (AV == "N" or PR == "N" or UI == "N"):
        return "2"


def EQ2(AC, AT):
    if AC == "L" and AT == "N":
        return "0"
    else:
        return "1"


def EQ3(VC, VI, VA):
    if (VC == "H" and VI == "H"):
        return "0"
    if not (VC == "H" and VI == "H") and (VC == "H" or VI == "H" or VA == "H"):
        return "1"
    if not (VC == "H" or VI == "H" or VA == "H"):
        return "2"


def EQ4(MSI, MSA, SC, SI, SA):
    if (MSI == "S" and MSA == "S"):
        return "0"
    if not (MSI == "S" or MSA == "S") and (SC == "H" or SI == "H" or SA == "H"):
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

    print(f'vektor w funkcji {vector}')

    print('metryki')
    for metric in METRIC_LEVELS:
        print(f" metryka {metric}")
        effective_metric_value = vector[metric]
        print(f" wartość metryki {effective_metric_value}")

        extracted_metric_value = extractValueMetric(metric, max_vector)
        print(f"wartość z max wektora {extracted_metric_value}")

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

VectorInput()