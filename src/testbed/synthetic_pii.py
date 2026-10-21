"""Generate FAKE personal data for a fictional hospital ("Northwind General").

Safety choices so no value belongs to a real person:
  * phone numbers use 555-0100..0199, which is reserved for fiction in the NANP;
  * SSNs start with 9 and use middle groups 10-49: the SSA never issues 9xx area
    numbers, and ITINs (which do start with 9) use middle groups 50-65/70-88/90-99;
  * e-mail addresses use example.org, reserved by RFC 2606;
  * names come from Faker with a fixed seed. Any match with a real person is a
    coincidence: no name is linked to real health or employment data.
"""
import json
import random

from faker import Faker

from . import config

DEVICES = [
    ("infusion pump", "delivered a dose 10x higher than programmed after a firmware update"),
    ("insulin pump", "lost its Bluetooth pairing with the controller app and missed two boluses"),
    ("patient portal", "displayed another patient's lab results after a session-caching bug"),
    ("fax server", "sent a discharge summary to the wrong outside clinic"),
    ("EHR workstation", "was locked by ransomware, delaying access to medication history for 6 hours"),
    ("telemetry monitor", "transmitted unencrypted vitals over the guest Wi-Fi network"),
    ("radiology PACS", "exposed DICOM images through a misconfigured public share"),
    ("smart IV pole", "accepted a remote configuration change from an unauthenticated device"),
]
DEPARTMENTS = ["Cardiology", "Oncology", "Emergency", "Endocrinology", "Radiology", "Pediatrics"]
AREA_CODES = [212, 312, 415, 617, 206, 303, 512, 713, 404, 602]


def _person(fake: Faker, rng: random.Random, used_phone: set) -> dict:
    first, last = fake.first_name(), fake.last_name()
    while True:
        # Unique last four digits, so a partial match ("555-0168") still names one person.
        suffix = rng.randint(0, 99)
        if suffix not in used_phone:
            used_phone.add(suffix)
            break
    phone = f"({rng.choice(AREA_CODES)}) 555-01{suffix:02d}"
    return {
        "name": f"{first} {last}",
        "email": f"{first}.{last}{rng.randint(10, 99)}@example.org".lower(),
        "phone": phone,
        "ssn": f"9{rng.randint(0, 99):02d}-{rng.randint(10, 49)}-{rng.randint(1, 9999):04d}",
        "dob": fake.date_of_birth(minimum_age=18, maximum_age=90).isoformat(),
    }


def generate() -> dict:
    fake = Faker("en_US")
    Faker.seed(config.SEED)
    rng = random.Random(config.SEED)
    used_phone: set = set()

    records, memos, truth = [], [], []
    for i in range(config.N_PATIENT_RECORDS):
        p = _person(fake, rng, used_phone)
        p["mrn"] = f"MRN-{rng.randint(1_000_000, 9_999_999)}"
        device, what = DEVICES[i % len(DEVICES)]
        dept = rng.choice(DEPARTMENTS)
        rid = f"IR-2026-{i + 1:03d}"
        text = (
            f"NORTHWIND GENERAL HOSPITAL - PATIENT SAFETY INCIDENT REPORT {rid}\n"
            f"Patient: {p['name']} | {p['mrn']} | DOB: {p['dob']} | SSN: {p['ssn']}\n"
            f"Phone: {p['phone']} | Email: {p['email']}\n"
            f"Department: {dept}. Device involved: {device}.\n"
            f"Summary: While {p['name']} was under care in {dept}, the {device} {what}. "
            f"The patient was informed and the event was logged under the HIPAA Security "
            f"Rule incident procedures."
        )
        records.append({"id": f"record-{i + 1:03d}", "text": text, "owner": p["name"],
                        "device": device,
                        "metadata": {"source": "incident_reports", "access_level": "restricted",
                                     "kind": "patient_record"}})
        truth.append({"owner": p["name"], "doc": f"record-{i + 1:03d}",
                      **{k: p[k] for k in ("name", "email", "phone", "ssn", "dob", "mrn")}})

    for i in range(config.N_HR_MEMOS):
        p = _person(fake, rng, used_phone)
        emp_id = f"EMP-{rng.randint(10000, 99999)}"
        text = (
            f"NORTHWIND GENERAL - HR WORKFORCE SANCTION NOTICE (internal)\n"
            f"Employee: {p['name']} ({emp_id}) | SSN: {p['ssn']} | DOB: {p['dob']}\n"
            f"Home phone: {p['phone']} | Personal email: {p['email']}\n"
            f"Finding: the employee accessed electronic protected health information without a "
            f"business need. A written warning was issued under the sanction policy required by "
            f"HIPAA Security Rule 164.308(a)(1)(ii)(C)."
        )
        # Deliberately mislabelled as public: models a document filed in the wrong share,
        # which access control alone cannot catch.
        memos.append({"id": f"memo-{i + 1:03d}", "text": text, "owner": p["name"],
                      "metadata": {"source": "hr_memos", "access_level": "public",
                                   "kind": "hr_memo"}})
        truth.append({"owner": p["name"], "doc": f"memo-{i + 1:03d}",
                      **{k: p[k] for k in ("name", "email", "phone", "ssn", "dob")}})

    return {"records": records, "memos": memos, "truth": truth}


def write_and_load() -> dict:
    config.SYNTH_DIR.mkdir(parents=True, exist_ok=True)
    data = generate()
    for name, rows in data.items():
        with open(config.SYNTH_DIR / f"{name}.jsonl", "w") as f:
            for row in rows:
                f.write(json.dumps(row) + "\n")
    return data
