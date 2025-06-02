## this is for eval purposes only 


import data as d
if __name__ == "__main__":

    
    # Generate 100 records
    for i in range(100):
        record = f"Pat ientID:{i}, Diagnosis:X, Notes:Bulk test\n" * 2000  # ~50KB per record
    d.encrypt_data(record, "admin", debug=False)


    # Generate large dummy patient data (~5MB)
    base_line = "PatientID:12345, Diagnosis:Hypertension, Medication:Lisinopril, Notes:None\n"
    sample_data = base_line * 100_000  # Roughly ~5MB

    print(f"Sample data size: {len(sample_data) / (1024 * 1024):.2f} MB")

    print("🔐 Running encryption with large data...\n")
    d.encrypt_data(sample_data.strip(), "admin", debug=True)

    print("\n🔓 Running decryption with large data...\n")
    d.decrypt_data("Admin", debug=True)



    
