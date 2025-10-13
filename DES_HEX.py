import logging
from DES_table import IP, FP, E, P, PC1, PC2, SHIFT_SCHEDULE, S_BOXES

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# -----------------------------
# Daftar Fungsi (overview)
# -----------------------------
# str_to_bit_array(text)            -> Ubah string jadi list bit
# bit_array_to_str(array)           -> Ubah list bit jadi string
# permute(block, table, name)       -> Terapkan tabel permutasi
# split_list(a, n)                  -> Bagi list jadi potongan ukuran n (split bit)
# xor(t1, t2)                       -> XOR antara dua list bit
# shift_left(lst, n)                -> Geser list bit ke kiri (mirip LR cuman geser tiap ronde)
# bits_to_hex(bits)                 -> Ubah list bit jadi string hex
# generate_keys(key_bits)           -> Buat 16 subkey DES
# substitute(expanded_half_block)   -> Substitusi S-Box
# feistel(right, subkey, round_num) -> Fungsi Feistel per ronde
# des_rounds(block, keys, encrypt)  -> DES 16 ronde encrypt/decrypt
# pad_text(text)                    -> Tambah padding (Nambahin extra chara) 
# unpad_text(text)                  -> Hapus padding
# encrypt(plaintext, key)           -> Enkripsi DES level tinggi
# decrypt(cipher_bits, key)         -> Dekripsi DES level tinggi

#----------------------------- Helper Conversion Tools-----------------------------
def str_to_bit_array(text: str):
    array = []
    for char in text:
        binval = bin(ord(char))[2:].rjust(8, '0')
        array.extend(int(x) for x in binval)
    logging.debug(f"[STR->BITS] '{text}' -> {array}")
    return array

def bit_array_to_str(array):
    res = ''.join(chr(int(''.join(map(str, array[i:i + 8])), 2))
                  for i in range(0, len(array), 8))
    logging.debug(f"[BITS->STR] {array} -> '{res}'")
    return res

def permute(block, table, name="PERMUTE"):
    result = [block[x - 1] if x - 1 < len(block) else 0 for x in table]
    logging.debug(f"[{name}] Input: {bits_to_hex(block)} -> Output: {bits_to_hex(result)}")
    return result

def split_list(a, n):
    return [a[i:i + n] for i in range(0, len(a), n)]

def xor(t1, t2):
    result = [x ^ y for x, y in zip(t1, t2)]
    logging.debug(f"[XOR] {bits_to_hex(t1)} XOR {bits_to_hex(t2)} -> {bits_to_hex(result)}")
    return result

def shift_left(lst, n):
    result = lst[n:] + lst[:n]
    logging.debug(f"[SHIFT_LEFT {n}] {bits_to_hex(lst)} -> {bits_to_hex(result)}")
    return result

def bits_to_hex(bits):
    bit_str = ''.join(str(b) for b in bits)
    length = len(bits) // 4
    return f"{int(bit_str, 2):0{length}x}"

#----------------------------- Key Schedule-----------------------------
def generate_keys(key_bits):
    keys = []
    key_permuted = permute(key_bits, PC1, name="PC1")
    C, D = key_permuted[:28], key_permuted[28:]
    logging.info(f"[KEY] Original bits after PC1 split: C0={bits_to_hex(C)}, D0={bits_to_hex(D)}")

    for i, shift_val in enumerate(SHIFT_SCHEDULE):
        C = shift_left(C, shift_val)
        D = shift_left(D, shift_val)
        combined = C + D
        subkey = permute(combined, PC2, name=f"PC2 Round {i+1}")
        keys.append(subkey)
        logging.info(f"[SUBKEY {i+1}] Hex: {bits_to_hex(subkey)}")

    return keys

#----------------------------- Feistel Functions-----------------------------
def substitute(expanded_half_block):
    blocks = split_list(expanded_half_block, 6)
    result = []
    for i in range(8):
        block = blocks[i]
        row = (block[0] << 1) + block[5]
        column = int(''.join(map(str, block[1:5])), 2)
        val = S_BOXES[i][row][column]
        binval = bin(val)[2:].rjust(4, '0')
        result += [int(x) for x in binval]
    return result

def feistel(right, subkey, round_num=None):
    expanded = permute(right, E, name="EXPAND")
    logging.info(f"[ROUND {round_num}] Right expanded: {bits_to_hex(expanded)}")
    
    temp = xor(expanded, subkey)
    logging.info(f"[ROUND {round_num}] XOR with subkey: {bits_to_hex(temp)}")
    
    substituted = substitute(temp)
    logging.info(f"[ROUND {round_num}] After S-Boxes: {bits_to_hex(substituted)}")
    
    permuted = permute(substituted, P, name="P-PERM")
    logging.info(f"[ROUND {round_num}] After P-Permutation: {bits_to_hex(permuted)}")
    return permuted

#----------------------------- DES Core-----------------------------
def des_rounds(block, keys, encrypt=True):
    block = permute(block, IP, name="IP")
    logging.info(f"[IP] After Initial Permutation: {bits_to_hex(block)}")
    
    left, right = block[:32], block[32:]
    round_order = range(16) if encrypt else reversed(range(16))

    for i in round_order:
        subkey = keys[i]
        temp = right
        f_result = feistel(right, subkey, round_num=i+1)
        right = xor(left, f_result)
        left = temp
        logging.info(f"[ROUND {i+1}] L={bits_to_hex(left)}, R={bits_to_hex(right)}")

    combined = right + left
    final_block = permute(combined, FP, name="FP")
    logging.info(f"[FP] After Final Permutation: {bits_to_hex(final_block)}")
    return final_block

# -----------------------------Padding-----------------------------
def pad_text(text):
    pad_len = 8 - (len(text) % 8)
    padded = text + chr(pad_len) * pad_len
    logging.info(f"[PADDING] Added {pad_len} byte(s).")
    return padded

def unpad_text(text):
    pad_len = ord(text[-1])
    if pad_len < 1 or pad_len > 8:
        return text
    logging.info(f"[UNPAD] Removed {pad_len} byte(s).")
    return text[:-pad_len]

# -----------------------------High-Level Encrypt/Decrypt-----------------------------

def encrypt(plaintext: str, key: str):
    if len(key) != 8:
        raise ValueError("Key must be exactly 8 characters long.")

    plaintext = pad_text(plaintext)
    logging.info(f"[PLAINTEXT PADDED] '{plaintext}'")

    key_bits = str_to_bit_array(key)
    logging.info(f"[KEY] Original key bits: {bits_to_hex(key_bits)}")
    keys = generate_keys(key_bits)

    result_bits = []
    for block_text in split_list(str_to_bit_array(plaintext), 64):
        encrypted_block = des_rounds(block_text, keys, encrypt=True)
        result_bits.extend(encrypted_block)

    logging.info("[ENCRYPTION COMPLETE]")
    return ''.join(map(str, result_bits))

def decrypt(cipher_bits, key: str):
    if len(key) != 8:
        raise ValueError("Key must be exactly 8 characters long.")

    if isinstance(cipher_bits, str):
        cipher_bits = [int(b) for b in cipher_bits]

    key_bits = str_to_bit_array(key)
    keys = generate_keys(key_bits)

    result_bits = []
    for block_bits in split_list(cipher_bits, 64):
        decrypted_block = des_rounds(block_bits, keys, encrypt=False)
        result_bits.extend(decrypted_block)

    decrypted_text = bit_array_to_str(result_bits)
    return unpad_text(decrypted_text)


# ----------------------------- Main Runner -----------------------------

if __name__ == "__main__":
    logging.getLogger().setLevel(logging.INFO)
    plaintext = input("Enter plaintext: ")
    while True:
        key = input("Enter 8-char key: ")
        if len(key) == 8:
            break
        logging.warning("Key must be exactly 8 characters long.")

    logging.info("=== ENCRYPTION START ===")
    cipher_bits = encrypt(plaintext, key)
    logging.info(f"Cipher bits (len={len(cipher_bits)}): {bits_to_hex([int(b) for b in cipher_bits])}")

    logging.info("=== DECRYPTION START ===")
    decrypted = decrypt(cipher_bits, key)
    print(f"\nDecrypted text: {decrypted}")
