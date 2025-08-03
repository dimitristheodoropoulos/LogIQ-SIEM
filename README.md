LogIQ: Εργαλείο Ανάλυσης Λογαριασμών και Ανίχνευσης Ασφαλείας

Ένα ολοκληρωμένο εργαλείο βασισμένο σε Python που αναλύει logs συστήματος, ανιχνεύει επιθέσεις (όπως brute-force), και παρέχει δεδομένα μέσω ενός RESTful API και ενός command-line interface (CLI). Το LogIQ στοχεύει στην παροχή βασικών λειτουργιών SIEM (Security Information and Event Management) για μικρά περιβάλλοντα ή ως βάση για περαιτέρω ανάπτυξη, αναδεικνύοντας τις δεξιότητές μου στην ανάπτυξη λογισμικού και την κυβερνοασφάλεια.
Χαρακτηριστικά

    RESTful API (Flask): Παρέχει endpoints για ασφαλή πρόσβαση και διαχείριση δεδομένων γεγονότων, ειδοποιήσεων και αναφορών. Περιλαμβάνει:

        JWT (JSON Web Token): Για ασφαλή πιστοποίηση χρήστη.

        Rate Limiting: Για προστασία από κατάχρηση και επιθέσεις DoS.

        Ενσωματωμένο σύστημα logging: Για παρακολούθηση της εφαρμογής και καταγραφή σφαλμάτων.

        Δυνατότητα Export Δεδομένων: Εξαγωγή γεγονότων και αναφορών σε JSON και CSV/PDF.

    CLI Εργαλείο: Για parsing logs, ανίχνευση alerts και παραγωγή reports απευθείας από τη γραμμές εντολών.

    Επεξεργασία Λογαριασμών (Log Parsing): Αναλύει και κατηγοριοποιεί γεγονότα από:

        Linux Authentication Logs (/var/log/auth.log ή /var/log/secure).

        Windows Authentication Event Logs (μέσω PowerShell script, απαιτείται προσαρμογή).

    Ανίχνευση Ασφαλείας: Εντοπίζει μοτίβα επιθέσεων και ανωμαλιών όπως:

        Brute-force επιθέσεις: Μέσω πολλαπλών αποτυχημένων logins.

        Ασυνήθιστες ώρες σύνδεσης χρηστών: Ανίχνευση ανωμαλιών βάσει ιστορικών δεδομένων.

    Διαχείριση Δεδομένων (NoSQL & SQL): Υποστηρίζει MongoDB για την αποθήκευση, ανάκτηση και ανάλυση των δεδομένων γεγονότων και χρηστών. Παρέχεται επίσης υλοποίηση για SQLite ως εναλλακτική λύση.

    Modular Σχεδιασμός: Καθαρή αρχιτεκτονική με διαχωρισμό σε modules (API, DB, Parsers, Detectors, Reports, CLI), διευκολύνοντας την επέκταση και τη συντήρηση.

Αρχιτεκτονική Overview

Το LogIQ αποτελείται από τα ακόλουθα βασικά συστατικά:

    main.py: Το κύριο σημείο εισόδου της εφαρμογής. Διαχειρίζεται την αρχική ρύθμιση (φόρτωση logs, σύνδεση DB), εκκινεί τον Flask web server και χειρίζεται τις γενικές εξαιρέσεις και τις εξαιρέσεις JWT.

    api/routes.py: Ορίζει όλα τα API endpoints (π.χ., /login, /events, /alerts). Χειρίζεται την πιστοποίηση JWT, τον έλεγχο σύνδεσης με τη βάση δεδομένων και την επικοινωνία με τα υπόλοιπα modules.

    cli/runner.py: Το script της γραμμής εντολών που επιτρέπει την εκτέλεση λειτουργιών όπως parsing logs, alerts και reports ανεξάρτητα από το API.

    db/: Περιέχει modules για αλληλεπίδραση με τη βάση δεδομένων:

        db_mongo.py: Υλοποίηση για MongoDB.

        db_sqlite.py: Υλοποίηση για SQLite.

    detectors/: Περιέχει αλγόριθμους για την ανίχνευση συγκεκριμένων τύπων επιθέσεων και ανωμαλιών (π.χ., anomalies.py, brute_force.py).

    parsers/: Υπεύθυνος για την ανάλυση ακατέργαστων γραμμών log σε δομημένα γεγονότα (π.χ., auth_parser.py).

    reports/: Περιέχει τη λογική για την παραγωγή διαφόρων αναφορών από τα συλλεγμένα δεδομένα (π.χ., report_generator.py).

    utils/config.py: Βοηθητικές συναρτήσεις, όπως η φόρτωση του αρχείου config.yaml.

    config.yaml: Αρχείο διαμόρφωσης για διαδρομές log, ρυθμίσεις βάσης δεδομένων και παραμέτρους ανίχνευσης.

Τεχνολογίες που Χρησιμοποιούνται

    Python 3.8+

    Flask: Web framework για το RESTful API.

    Flask-JWT-Extended: Για JWT authentication.

    PyMongo: Python driver για MongoDB.

    SQLite3: Ενσωματωμένη βάση δεδομένων (μέσω του sqlite3 module της Python).

    jsonschema: Για επικύρωση δεδομένων εισόδου API.

    Pytest: Για δοκιμές μονάδων και ολοκλήρωσης.

    Werkzeug: Για hashing κωδικών πρόσβασης.

Εγκατάσταση και Εκτέλεση

Για να θέσετε σε λειτουργία το LogIQ, ακολουθήστε τα παρακάτω βήματα:
Προαπαιτούμενα

    Python 3.8+

    pip (περιλαμβάνεται συνήθως με την Python)

    MongoDB Server: Βεβαιωθείτε ότι ένας MongoDB server τρέχει στο localhost στην προεπιλεγμένη θύρα 27017 (ή όπως διαμορφώνεται στο config.yaml). Αν χρησιμοποιείτε Docker, βεβαιωθείτε ότι το container του MongoDB είναι ενεργό.

Βήματα Εγκατάστασης

    Κλωνοποίηση του αποθετηρίου:

    git clone [https://github.com/YOUR_GITHUB_USERNAME/logiq.git](https://github.com/YOUR_GITHUB_USERNAME/logiq.git) # <--- ΑΝΤΙΚΑΤΑΣΤΗΣΤΕ ΜΕ ΤΟ ΠΡΑΓΜΑΤΙΚΟ ΣΑΣ URL
    cd logiq

    Δημιουργία και ενεργοποίηση virtual environment:
    Συνιστάται η χρήση ενός virtual environment για την απομόνωση των εξαρτήσεων.

    python3 -m venv venv
    source venv/bin/activate

    (Για Windows Command Prompt: venv\Scripts\activate.bat, για PowerShell: venv\Scripts\Activate.ps1)

    Εγκατάσταση dependencies:
    Εγκαταστήστε όλα τα απαραίτητα πακέτα Python.

    pip install -r requirements.txt

    Δημιουργία αρχείου .env:
    Δημιουργήστε ένα αρχείο με όνομα .env στο root directory του project σας (~/projects/logiq/) και προσθέστε τις ακόλουθες περιβαλλοντικές μεταβλητές:

    FLASK_DEBUG=False
    FLASK_HOST=0.0.0.0
    FLASK_PORT=5000
    JWT_SECRET_KEY=ΜΙΑ_ΠΟΛΥ_ΙΣΧΥΡΗ_ΚΑΙ_ΜΟΝΑΔΙΚΗ_ΜΥΣΤΙΚΗ_ΛΕΞΗ_ΓΙΑ_ΤΗΝ_ΠΑΡΑΓΩΓΗ

        Σημείωση: Για την παραγωγή, ορίστε FLASK_DEBUG=False. Το JWT_SECRET_KEY είναι κρίσιμο για την ασφάλεια.

    Ρύθμιση config.yaml:
    Βεβαιωθείτε ότι το αρχείο config.yaml είναι ρυθμισμένο σωστά, ειδικά οι διαδρομές των logs και τα στοιχεία σύνδεσης της βάσης δεδομένων.

    # Παράδειγμα config.yaml
    log_paths:
      - logs/test_auth.log # Ή άλλες διαδρομές log αρχείων
      # - /var/log/auth.log # Για Linux
      # - C:\Path\To\Windows\Security.evtx # Για Windows, αν το PowerShell το εξάγει σε αρχείο

    database:
      type: mongodb # ή sqlite
      uri: "mongodb://localhost:27017" # ή "logiq_siem.db" για SQLite
      db_name: "logiq"

    alerts:
      failed_login_threshold: 5

    anomalies:
      failed_login_user_threshold: 5
      failed_login_ip_threshold: 10
      unusual_hour_min_logins: 2

Εκτέλεση της Εφαρμογής

Μόλις ολοκληρώσετε τα παραπάνω βήματα, βεβαιωθείτε ότι το virtual environment είναι ενεργό και εκτελέστε:

python main.py

Η εφαρμογή θα ξεκινήσει, θα συνδεθεί στη διαμορφωμένη βάση δεδομένων (MongoDB ή SQLite), θα πραγματοποιήσει αρχικό φόρτο δεδομένων από τα διαμορφωμένα logs και θα εκκινήσει τον Flask server στη διεύθυνση που ορίζεται στο .env (π.χ., http://127.0.0.1:5000).
Χρήση CLI Εργαλείων

Τα CLI εργαλεία παρέχονται μέσω του main.py με την επιλογή --mode cli. Βεβαιωθείτε ότι το virtual environment είναι ενεργό πριν από την εκτέλεση:

    Ανάγνωση logs και αποθήκευση στη βάση:

    python main.py --mode cli --cli-command parse-logs

    Ανίχνευση alerts:

    python main.py --mode cli --cli-command alerts

    Δημιουργία βασικού report (για παράδειγμα, για 24 ώρες):

    python main.py --mode cli --cli-command report --time-window 24h

    Δοκιμή σύνδεσης βάσης δεδομένων:

    python main.py --mode cli --cli-command db-test

    Για βοήθεια και επιλογές:

    python main.py --help

REST API Endpoints

Αφού εκτελέσετε την εφαρμογή, μπορείτε να αλληλεπιδράσετε με τα ακόλουθα endpoints. Όλα τα protected endpoints απαιτούν έγκυρο JWT access token στο header Authorization: Bearer <token>.
Authentication & Authorization

    /api/register (POST): Δημιουργία νέου χρήστη.

        Payload: {"username": "your_username", "password": "your_password"}

        Response: {"message": "Επιτυχής εγγραφή χρήστη", "user_id": "..."} (201 Created)

    /api/login (POST): Σύνδεση χρήστη και λήψη JWT.

        Payload: {"username": "your_username", "password": "your_password"}

        Response: {"access_token": "your_jwt_token"} (200 OK)

Event & Alert Management

    /api/events (POST): Επιτρέπει την εισαγωγή νέων γεγονότων ασφαλείας στην πλατφόρμα.

        Payload: [{"timestamp": "YYYY-MM-DDTHH:MM:SSZ", "hostname": "host1", "event_type": "login_attempt", "message": "Login failed for user X from IP Y", "ip": "Y.Y.Y.Y", "details": {"user": "userX"}}] (Λίστα γεγονότων)

        Requires: JWT Token

        Response: {"message": "Events added successfully", "events": [...]} (201 Created)

    /api/alerts (GET): Επιστρέφει ενεργές ειδοποιήσεις από τους ανιχνευτές.

        Parameters: ?threshold=<int>&time_window=<value><unit> (π.χ., ?threshold=5&time_window=24h για 24 ώρες ή 7d για 7 ημέρες)

        Requires: JWT Token

    /api/anomalies (GET): Επιστρέφει αναφορές για ανωμαλίες (π.χ., ασυνήθιστες ώρες σύνδεσης).

        Parameters: ?failed_window=<int_minutes>&historical_window=<int_days>

        Requires: JWT Token

Reporting & Exporting

    /api/report (POST): Δημιουργεί και επιστρέφει μια σύνοψη αναφοράς.

        Payload: {"time_window": "<value><unit>"} (π.χ., {"time_window": "24h"})

        Requires: JWT Token

        Response: {"summary": {...}} (200 OK)

    /api/report/export (GET): Εξάγει την αναφορά σε αρχείο.

        Parameters: ?format=<json|pdf>&time_window=<value><unit> (π.χ., ?format=pdf&time_window=7d)

        Requires: JWT Token

    /api/export (GET): Εξάγει όλα τα γεγονότα.

        Parameters: ?format=<json|csv> (π.χ., ?format=json)

        Requires: JWT Token

Health Checks (Προγραμματισμένες)

    /api/status (GET): Επιστρέφει την κατάσταση της εφαρμογής. (Προγραμματισμένο)

    /api/metrics (GET): Placeholder για metrics. (Προγραμματισμένο)

Σκέψεις Ασφάλειας και Βέλτιστες Πρακτικές

Το LogIQ ενσωματώνει αρκετές βέλτιστες πρακτικές ασφαλείας:

    JWT Authentication: Χρήση JSON Web Tokens για ασφαλή πιστοποίηση χρήστη.

    Password Hashing: Αποθήκευση passwords μόνο σε κρυπτογραφημένη μορφή (bcrypt) στη βάση δεδομένων.

    Rate Limiting: Περιορισμός των αιτημάτων στα API endpoints για την αποτροπή DoS/brute-force επιθέσεων.

    Structured Logging: Καταγραφή γεγονότων και σφαλμάτων με λεπτομερείς πληροφορίες.

    Input Validation: Βασικοί έλεγχοι εισόδου στα API endpoints για την αποτροπή κοινών προβλημάτων (μέσω jsonschema).

Προτεινόμενες μελλοντικές βελτιώσεις για ασφάλεια:

    Πιο ολοκληρωμένο audit trail για όλες τις ενέργειες χρήστη.

    Κρυπτογράφηση ευαίσθητων πεδίων στη βάση δεδομένων (αν δεν είναι ήδη καλυμμένο από το hashing).

    Ενσωμάτωση με OAuth2 ή OpenID Connect για ισχυρότερη αυθεντικοποίηση.

Σενάρια Χρήσης / SIEM-like Λειτουργίες

Το LogIQ μπορεί να χρησιμοποιηθεί για:

    Συλλογή και Αποθήκευση Λογαριασμών: Κεντρική αποθήκευση logs από διάφορα συστήματα.

    Ανάλυση Συμβάντων: Εξαγωγή δομημένων πληροφοριών από ακατέργαστα logs.

    Ανίχνευση Απειλών: Εντοπισμός ύποπτων δραστηριοτήτων όπως:

        Brute-force επιθέσεις.

        Ασυνήθιστες συμπεριφορές σύνδεσης (π.χ., σύνδεση σε άγνωστες ώρες).

    Δημιουργία Αναφορών: Παροχή συνοπτικών πληροφοριών για την κατάσταση ασφαλείας.

    Πλατφόρμα για SecOps: Μπορεί να λειτουργήσει ως βάση για μια απλή πλατφόρμα Security Operations, επιτρέποντας στους αναλυτές να αναζητούν συμβάντα και να εντοπίζουν ανωμαλίες.

Δοκιμές (Testing)

Το LogIQ περιλαμβάνει μια ολοκληρωμένη σουίτα δοκιμών για τη διασφάλιση της λειτουργικότητας και της αξιοπιστίας. Χρησιμοποιούμε το pytest για την εκτέλεση των δοκιμών και το coverage.py για την παρακολούθηση της κάλυψης κώδικα.

Για να εκτελέσετε τις δοκιμές:

    Βεβαιωθείτε ότι το virtual environment είναι ενεργό.

    Εγκαταστήστε τις εξαρτήσεις δοκιμών (αν δεν το έχετε κάνει ήδη):

    pip install pytest pytest-cov

    Εκτελέστε τις δοκιμές με αναφορά κάλυψης:

    pytest --cov=logiq

    Αυτό θα εκτελέσει όλες τις δοκιμές και θα εμφανίσει μια αναφορά κάλυψης κώδικα στο τέλος.

Συνεισφορά

Καλώς ήρθες να συνεισφέρεις στο LogIQ!

    Αναφορά Σφαλμάτων (Issues): Αν βρείτε κάποιο bug ή έχετε προτάσεις για βελτιώσεις, παρακαλώ ανοίξτε ένα issue στο GitHub.

    Αιτήματα Pull (Pull Requests): Είστε ευπρόσδεκτοι να υποβάλετε pull requests με νέες λειτουργίες, βελτιώσεις κώδικα ή διορθώσεις σφαλμάτων.