"""
Synthetic Clinical Data Generator for ArogyaRaksha.
Generates realistic, completely non-sensitive synthetic healthcare records
for development, testing, staging, and load benchmarks.
Conforms strictly to privacy-by-design: zero real-world PHI is used.
"""
import random
import secrets
from typing import Any

FIRST_NAMES = [
    "Aarav", "Vivaan", "Aditya", "Vihaan", "Arjun", "Sai", "Reyansh", "Ayaan",
    "Krishna", "Ishaan", "Diya", "Saanvi", "Ananya", "Aadhya", "Pari", "Chiara",
    "Fatima", "Zara", "Kavya", "Myra", "Anika", "Riya", "Isha", "Tara"
]

LAST_NAMES = [
    "Sharma", "Patel", "Verma", "Rao", "Reddy", "Kulkarni", "Deshmukh", "Nair",
    "Iyer", "Mehta", "Bhat", "Joshi", "Das", "Chowdhury", "Singh", "Gupta"
]

AGE_BANDS = ["0-17", "18-29", "30-39", "40-49", "50-59", "60-69", "70+"]
GENDERS = ["Female", "Male", "Other"]

CONDITIONS = [
    ("Type 2 Diabetes Mellitus", "Metformin 500mg BID, lifestyle modification, dietary counseling"),
    ("Essential Hypertension", "Amlodipine 5mg QD, low sodium diet, blood pressure monitoring"),
    ("Bronchial Asthma", "Salbutamol MDI PRN, Fluticasone propionate inhaler BID"),
    ("Acute Viral Pharyngitis", "Paracetamol 650mg SOS, warm saline gargles, hydration"),
    ("Osteoarthritis (Bilateral Knees)", "Acetaminophen 1g TID, physical therapy, weight management"),
    ("Mild Community Acquired Pneumonia", "Azithromycin 500mg daily for 5 days, rest, hydration"),
    ("Gastroesophageal Reflux Disease", "Pantoprazole 40mg before breakfast, dietary changes"),
    ("Chronic Low Back Pain", "Physiotherapy regimen, ergonomic posture counseling"),
    ("Hyperlipidemia", "Atorvastatin 10mg at bedtime, lipid panel in 12 weeks"),
    ("Allergic Rhinitis", "Cetirizine 10mg HS, nasal saline spray"),
]


def generate_synthetic_patient(patient_index: int, tenant_id: str = "tenant-default") -> dict[str, Any]:
    """Generates a single synthetic patient dictionary."""
    first = secrets.choice(FIRST_NAMES)
    last = secrets.choice(LAST_NAMES)
    name = f"{first} {last}"
    age_band = secrets.choice(AGE_BANDS)
    gender = secrets.choice(GENDERS)
    condition, treatment = secrets.choice(CONDITIONS)

    patient_id = f"SYN-{tenant_id[:4].upper()}-{patient_index:05d}"
    notes = f"Routine synthetic clinical follow-up for {name}. Vitals within normal limits for {age_band} cohort."
    history = "No known drug allergies. Prior history of mild seasonal allergies. Non-smoker."

    return {
        "patient_id": patient_id,
        "name": name,
        "age_band": age_band,
        "gender": gender,
        "diagnosis": condition,
        "treatment": treatment,
        "medical_history": history,
        "notes": notes,
        "tenant_id": tenant_id
    }


def generate_synthetic_dataset(count: int = 50, tenant_id: str = "tenant-default") -> list[dict[str, Any]]:
    """Generates a batch of synthetic patient records."""
    random.seed(42 + hash(tenant_id) % 10000)
    return [generate_synthetic_patient(i + 1, tenant_id=tenant_id) for i in range(count)]


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Synthetic Data Generator")
    parser.add_argument("--count", type=int, default=10, help="Number of records to generate")
    parser.add_argument("--tenant", type=str, default="tenant-alpha", help="Tenant ID")
    args = parser.parse_args()

    records = generate_synthetic_dataset(args.count, tenant_id=args.tenant)
    print(f"[*] Generated {len(records)} synthetic clinical records for {args.tenant}:")
    for r in records[:3]:
        print(f"  - {r['patient_id']}: {r['name']} ({r['gender']}, {r['age_band']}) -> {r['diagnosis']}")
