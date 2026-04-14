from crypto_utils import generate_dek, encrypt_pii, decrypt_pii

dek = generate_dek()
original_text = "Ho so benh an cua Nguyen"

print("=== TEST 1: MA HOA HOP LE ===")
encrypted_b64 = encrypt_pii(original_text, dek)
print("Ciphertext (Gui cho Quyen):", encrypted_b64)
print("Giai ma thanh cong:", decrypt_pii(encrypted_b64, dek))

print("\n=== TEST 2: GIA LAP HACKER SUA DU LIEU (E-C3) ===")
modified_b64 = "A" + encrypted_b64[1:]
print("Ciphertext bi sua:", modified_b64)

try:
    decrypt_pii(modified_b64, dek)
except Exception as e:
    print("\n=> [BAO DONG] LOI TOAN VEN DU LIEU:", type(e).__name__, "-", e)
    print("=> CHI SO E-C3 DAT YEU CAU!")
    