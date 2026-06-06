FROM python:3.11-slim

WORKDIR /app

# Αντιγράφουμε πρώτα μόνο το requirements.txt
COPY requirements.txt .

# Εγκαθιστούμε τις εξαρτήσεις
RUN pip install --no-cache-dir -r requirements.txt

# Τώρα αντιγράφουμε όλα τα υπόλοιπα αρχεία
COPY . .

CMD ["python", "main.py"]
