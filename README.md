LogIQ: SIEM-ready Security Analytics & Detection
Το LogIQ είναι ένα ολοκληρωμένο εργαλείο ανάλυσης ασφαλείας, σχεδιασμένο για να καλύπτει το κενό ορατότητας σε μικρά και μεσαία περιβάλλοντα πληροφορικής. Προσφέρει δυνατότητες κεντρικής διαχείρισης log, αυτοματοποιημένης ανίχνευσης απειλών και παραγωγής αναφορών, λειτουργώντας ως μια στιβαρή βάση για SecOps δραστηριότητες.

Why LogIQ for a Cyber Analyst?
Το LogIQ αντικατοπτρίζει τις καθημερινές προκλήσεις ενός SOC Analyst: από το parsing ακατέργαστων logs, στην ανίχνευση brute-force επιθέσεων, μέχρι τη διασφάλιση ορατότητας σε κρίσιμα συστήματα.

Alignment with Security Operations Center (SOC) Operations
Το LogIQ έχει σχεδιαστεί για να υποστηρίζει τις βασικές δραστηριότητες ενός σύγχρονου κέντρου ασφαλείας, λειτουργώντας ως προσομοιωτής SIEM/XDR περιβάλλοντος:

Detection Capability Development: Επιτρέπει την ανάπτυξη και δοκιμή κανόνων ανίχνευσης (detection analytics) για τον εντοπισμό απειλών.

Incident Response (IR) Efforts: Η δομή του εργαλείου και το CLI επιτρέπουν την ταχεία λήψη δεδομένων και το correlation γεγονότων, υποστηρίζοντας την απόκριση σε πραγματικά περιστατικά (containment, eradication, remediation).

Visibility: Παρέχει centralized visibility σε authentication logs, που αποτελεί τον πυρήνα της λειτουργίας κάθε σύγχρονου SIEM.

Βασικά Χαρακτηριστικά
RESTful API (Flask): Ασφαλής διαχείριση με JWT Authentication και Rate Limiting.

CLI Εργαλείο: Παραγωγή αναφορών και parsing από το terminal για γρήγορη απόκριση (Incident Response).

Ανίχνευση Ασφαλείας: Αυτοματοποιημένα alerts για brute-force και ανωμαλίες (π.χ. unusual login hours).

Modular Σχεδιασμός: Καθαρή αρχιτεκτονική που διευκολύνει την επέκταση και τη συντήρηση.

Τεχνικές Ικανότητες (Technical Competencies)
Multi-OS Environment Analysis: Υποστήριξη για Linux (auth logs) και Windows (Event logs).

Scripting & Automation: Υλοποίηση σε Python για την αυτοματοποίηση της ανάλυσης.

Security-by-Design: Χρήση JWT, Password Hashing (bcrypt) και Input Validation (jsonschema).
Security Integration & Enterprise Ecosystem
Το LogIQ δεν αποτελεί μια απομονωμένη λύση, αλλά ένα εργαλείο σχεδιασμένο να ενσωματώνεται σε σύγχρονα οικοσυστήματα ασφαλείας:

Enterprise Integration: Το project υποστηρίζει τη διασύνδεση με industry-standard εργαλεία όπως το Wazuh, επιτρέποντας την κεντρική λήψη δεδομένων και τη βελτιστοποίηση του log aggregation.

Business Continuity: Με ενσωματωμένα scripts για Automated Backup & Restore (MongoDB), το LogIQ προσομοιώνει τις πραγματικές απαιτήσεις για τη διατήρηση της ακεραιότητας των δεδομένων και τη διαθεσιμότητα των συστημάτων (Business Continuity).

Cyber Resilience: Μέσω της αρχιτεκτονικής του, το εργαλείο επιδεικνύει την ικανότητα γεφύρωσης custom Python αυτοματισμών με καθιερωμένες πλατφόρμες SIEM, παρέχοντας στους αναλυτές τη δυνατότητα να ανταποκρίνονται με ταχύτητα και ακρίβεια σε σύνθετα περιστατικά κυβερνοασφάλειας.

Εγκατάσταση και Εκτέλεση
Disclaimer: Το LogIQ είναι ένα εργαλείο ανάλυσης ασφαλείας που σχεδιάστηκε για εκπαιδευτικούς σκοπούς και για την επίδειξη δυνατοτήτων SecOps σε προσομοιωμένα περιβάλλοντα.

Κλωνοποίηση: git clone [https://github.com/dimitristheodoropoulos/LogIQ-SIEM.git](https://github.com/dimitristheodoropoulos/LogIQ-SIEM.git)

Virtual Environment: python3 -m venv venv && source venv/bin/activate

Εξαρτήσεις: pip install -r requirements.txt

Environment: Δημιουργία αρχείου .env με τις απαραίτητες μεταβλητές (FLASK_PORT, JWT_SECRET_KEY).

Ρύθμιση: Διαμόρφωση του config.yaml για τις διαδρομές των logs και τη σύνδεση στη βάση (MongoDB/SQLite).

Εκτέλεση: python main.py

Testing & Quality Assurance
Το project ακολουθεί test-driven ανάπτυξη:

Test Coverage: Χρήση pytest και coverage.py.

Εκτέλεση δοκιμών: pytest --cov=logiq

Συνεισφορά
Το LogIQ είναι ανοιχτό σε βελτιώσεις μέσω Pull Requests. Ιδανικό για επέκταση με integration security feeds (π.χ. MISP/OTX) και περαιτέρω ανάπτυξη των SIEM δυνατοτήτων του για την ανίχνευση Advanced Persistent Threats (APTs).

Αναπτύχθηκε από τον Dimitris Theodoropoulos.
