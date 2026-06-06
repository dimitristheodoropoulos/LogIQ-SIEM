# LogIQ: SIEM-ready Security Analytics & Detection

Το **LogIQ** είναι ένα ολοκληρωμένο εργαλείο ανάλυσης ασφαλείας, σχεδιασμένο για να καλύπτει το κενό ορατότητας σε μικρά και μεσαία περιβάλλοντα πληροφορικής. Αναπτύχθηκε με γνώμονα τα πρότυπα **ISO 27001**, προσφέροντας δυνατότητες κεντρικής διαχείρισης log, αυτοματοποιημένης ανίχνευσης απειλών και παραγωγής αναφορών, λειτουργώντας ως μια στιβαρή βάση για SecOps δραστηριότητες.

### Why LogIQ for a Cyber Analyst?

Το LogIQ δεν είναι απλώς ένα SIEM prototype· είναι μια πλατφόρμα που αντικατοπτρίζει τις καθημερινές προκλήσεις ενός SOC Analyst: από το parsing ακατέργαστων logs, στην ανίχνευση lateral movement και brute-force επιθέσεων, μέχρι τη διασφάλιση συμμόρφωσης με πρότυπα ασφαλείας μέσω verifiable evidence.

## Alignment with Cyber Intelligence Center Operations

Το LogIQ έχει σχεδιαστεί για να υποστηρίζει τις βασικές δραστηριότητες ενός Cyber Intelligence Center (CIC), λειτουργώντας ως προσομοιωτής SIEM/XDR περιβάλλοντος:

* **Detection Capability Development:** Επιτρέπει την ανάπτυξη και δοκιμή κανόνων ανίχνευσης (detection analytics) για τον εντοπισμό απειλών που παρακάμπτουν τα συμβατικά controls.
* **Incident Response Support:** Η δυνατότητα εξαγωγής αναφορών και η χρήση του CLI επιτρέπουν την ταχεία λήψη δεδομένων, υποστηρίζοντας τη διαδικασία ανάλυσης και containment κατά τη διάρκεια ενός περιστατικού.
* **Advanced Cyber Analysis:** Μέσω του log parsing και της ανάλυσης ανωμαλιών, το εργαλείο βοηθά στην ανάλυση δραστηριότητας δικτύου και συστημάτων (network and system activity analysis).

## Τεχνικές Ικανότητες (Technical Competencies)

* **Multi-OS Environment Analysis:** Υποστήριξη για Linux (auth logs) και Windows (Event logs), ευθυγραμμισμένη με την ανάγκη για visibility σε ετερογενή περιβάλλοντα συστημάτων.
* **Scripting & Automation:** Υλοποίηση σε **Python** για την αυτοματοποίηση της ανάλυσης, μειώνοντας τον χρόνο που απαιτείται για την ανίχνευση απειλών.
* **Cybersecurity Frameworks:** Εστίαση σε τεχνολογίες που ενισχύουν την ανίχνευση επιθέσεων, προετοιμάζοντας την άμυνα ενάντια σε εξελιγμένες απειλές.

## Χαρακτηριστικά

* **RESTful API (Flask):** Ασφαλής διαχείριση με **JWT Authentication** και **Rate Limiting**.
* **CLI Εργαλείο:** Παραγωγή αναφορών και parsing από το terminal για γρήγορη απόκριση (Incident Response).
* **Ανίχνευση Ασφαλείας:** Αυτοματοποιημένα alerts για brute-force και ανωμαλίες (unusual login hours).
* **Modular Σχεδιασμός:** Καθαρή αρχιτεκτονική που διευκολύνει την επέκταση και τη συντήρηση.

## Quality Assurance & Testing

Το project ακολουθεί test-driven ανάπτυξη, διασφαλίζοντας την αξιοπιστία των μηχανισμών:

* **Test Coverage:** 100% pass rate στο suite των 78 αυτοματοποιημένων τεστ.
* **Εργαλεία:** Χρήση `pytest` για unit & integration testing και `jsonschema` για επικύρωση δεδομένων.
* **Εντολή εκτέλεσης:** `PYTHONPATH=. pytest tests/ -v`

## ISO 27001 & Security-by-Design

Το LogIQ ενσωματώνει βέλτιστες πρακτικές ασφαλείας:

* **Compliance:** Υλοποίηση ελέγχων A.8.15 (Logging), A.8.16 (Monitoring), A.8.8 (Vulnerability Management) και A.5.23 (Cloud Security) του ISO 27001.
* **Security-by-Design:** JWT Authentication, password hashing (bcrypt), και αυστηρό Input Validation μέσω `jsonschema`.

## Εγκατάσταση και Εκτέλεση

### Quick Start

1. **Clone & Setup:**
```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/logiq.git
cd logiq
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

```


2. **Environment (.env):** Ορίστε τα `FLASK_DEBUG=False` και `JWT_SECRET_KEY=YOUR_SECRET`.
3. **Run:** `python main.py`

## Αρχιτεκτονική Overview

* `main.py`: Entry point & Server initialization.
* `api/`: Routes & Auth logic.
* `detectors/`: Brute-force & anomaly detection logic.
* `db/`: Abstraction layer για MongoDB & SQLite.
* `parsers/`: Log normalization logic.

## Συνεισφορά

Το LogIQ είναι ανοιχτό σε βελτιώσεις (Issue / Pull Request). Ιδανικό για επέκταση με integration security feeds (π.χ. MISP/OTX) και περαιτέρω ανάπτυξη των SIEM δυνατοτήτων του.
