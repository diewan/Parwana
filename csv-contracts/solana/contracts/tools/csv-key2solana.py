import base58

# RUN: csv wallet private-key solana
private_key = "hex string" # Assume this is 128 chars long
# List comprehension to convert 2-char chunks to decimal
privatekey_decimal_list = [int(private_key[i:i+2], 16) for i in range(0, len(private_key), 2)]

# ------------------------------------------------------

# RUN: csv wallet list
# Replace with your actual Base58 string
solana_address = "base58 string"

# 1. Decode Base58 into raw bytes
byte_data = base58.b58decode(solana_address)

# 2. Convert each byte into its decimal number
publickey_decimal_list = [b for b in byte_data]


# ------------------------------------------------------

print("Solana Wallet :", privatekey_decimal_list + publickey_decimal_list)

