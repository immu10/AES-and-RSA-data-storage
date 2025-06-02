## this is for eval purposes only 
from datetime import datetime

import data as d


if __name__ == "__main__":
    print("🔐 Generating test records...\n")
    #currently records each records time and displays it per record need to fix sometime
    for i in range(100):
        # Each record will be ~50KB (adjust multiplier as needed)
        timestamp = datetime.now().isoformat()
        record = (
            f"PatientID:{i}, Diagnosis:SampleCase, Notes:This is a benchmark test. Timestamp:{timestamp}\n"
            * 2000
        )
        d.encrypt_data(record, "admin", debug=False)

    # # Generate 100 records
    # for i in range(100):
    #     record = f"Pat ientID:{i}, Diagnosis:X, Notes:Bulk test\n" * 2000  # ~50KB per record
    # d.encrypt_data(record, "admin", debug=False)


    # Generate large dummy patient data (~5MB)
    # base_line = "PatientID:12345, Diagnosis:Hypertension, Medication:Lisinopril, Notes:None\n"
    # sample_data = base_line * 100_000  # Roughly ~5MB

    # print(f"Sample data size: {len(sample_data) / (1024 * 1024):.2f} MB")

    # print("Running encryption with large data...\n")
    # d.encrypt_data(sample_data.strip(), "admin", debug=True)

    # print("\nRunning decryption with large data...\n")
    # d.decrypt_data("Admin", debug=True)



    
