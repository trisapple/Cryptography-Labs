def xor_bytes(b1, b2):
    """XORs two byte sequences."""
    return bytes([a ^ b for a, b in zip(b1, b2)])

def break_two_time_pad(c1_hex, c2_hex):
    # Convert hex ciphertexts from the lab to bytes [cite: 107, 108]
    c1 = bytes.fromhex(c1_hex)
    c2 = bytes.fromhex(c2_hex)
    
    # Calculate P1 ^ P2
    xor_sum = xor_bytes(c1, c2)
    
    print(f"XOR Result (P1 ^ P2) in Hex:\n{xor_sum.hex()}\n")
    
    # Helper function for Crib Dragging
    def drag_crib(crib, xor_result):
        print(f"{'Offset':<8} | {'Resulting Text'}")
        print("-" * 30)
        crib_bytes = crib.encode()
        for i in range(len(xor_result) - len(crib_bytes) + 1):
            target_slice = xor_result[i : i + len(crib_bytes)]
            result = xor_bytes(target_slice, crib_bytes)
            # Filter non-printable characters for cleaner output
            readable = "".join([chr(b) if 32 <= b <= 126 else "." for b in result])
            print(f"{i:<8} | {readable}")

    # Start by guessing a common word like "the " or "This "
    guess = input("Enter a crib to test (e.g., 'the '): ")
    drag_crib(guess, xor_sum)

if __name__ == "__main__":
    # Ciphertexts provided in the lab document
    ciphertext1 = "654d1326304618fab96ec5cfeca981df63466513e16bc8fe981ed215d4c876436fc950ab87f779" # to be or not to be that is the question
    ciphertext2 = "78441325214611e1eb73de9bb5b29bdf654c6509e67e9cad840e9104d9c9764668d503be89f97e81" # if at first you do not succeed try again
    
    break_two_time_pad(ciphertext1, ciphertext2)