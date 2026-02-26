import sys, math

# Function to compute the key of a chiphertext encrypted by a shift cipher  
def get_key_shift(ct):
    # Hardcoded frequencies for English characters    
    p = [0.082, 0.015, 0.028, 0.042, 0.127, 0.022, 0.020, 0.061, 0.070, 0.001, 0.008, 0.040, 0.024,
    0.067, 0.075, 0.019, 0.001, 0.060, 0.063, 0.090, 0.028, 0.010, 0.024, 0.002, 0.020, 0.001]

    # Compute character frequencies for ciphertext ct (array q)
    # Compute counts then divide by size
    q = []
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    for letter in alphabet:
        q.append(ct.count(letter)) # Count of each letter in an array from A to Z
    for i in range(26):
        q[i] /= len(ct) # Divide each count by total length of ciphertext to get frequency

    # Compute index of coincidence for different shift values j
    # Key value is maintained into variable key (max IOC)
    max_ioc = 0
    for j in range(26):
        ioc = 0.0
        for i in range(26):
            ioc += p[i]*q[(i+j)%26] # Statistical Attack Method, refer to 1.2 Notes

        if ioc > max_ioc:
            max_ioc = ioc
            key = j

    return key


def main():	
    # Check whether input file name is provided
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} input-file\n")
        sys.exit()

    # Open file, exit if error
    try:
        file = open(sys.argv[1], "r");
    except IOError:
        print(f"Error: can\'t open file {sys.argv[1]}")
        sys.exit()

    # Read ciphertext into string ct and convert to uppercase
    ct = file.read()
    ct = ct.upper()

    # Compute index of coincidence for different key lengths k (from 1 to 20)
    s = []
    for k in range(1,21,1):
        tmp = [] # Temporary list to store extracted ciphertext
        q = [0]*26 # Letter frequencies initialized to 0
        # Extract a letter from the ciphertext every 1 position, 2 positions, ..., k positions starting from position 0
        for i in range(0,len(ct),k):
            tmp.append(ct[i])

        # Compute character frequencies for ciphertext tmp (array q)
        # Compute counts then divide by len(tmp)
        for i in range(len(tmp)):
            q[ord(tmp[i])-ord('A')] += 1 # Iterate the ciphertext in tmp and increment count for that letter in tmp
        for i in range(26):
            q[i] /= len(tmp) # Divide each letter count by total length of ciphertext to get frequency

        # Compute index of coincidence (refer to 1.2 Notes) and store it into list s
        ioc = 0.0;
        for i in range(26):
            ioc += q[i] * q[i] # Square each frequency and sum them up for each key length
        s.append(ioc)
        
    for i in range(20):
        print(f"{i+1}: {s[i]}")

    # Find key lengths where IOC is close to English (0.065)
    # Look for IOC values that are significantly higher than random (0.038)
    # English text has IOC around 0.065, random text around 0.038
    candidates = []
    for i in range(20):
        if s[i] >= 0.075:  # Look for significantly high IOC values
            candidates.append(i+1)  # Store 1-indexed key length
    
    # Find the smallest candidate that divides many others
    if len(candidates) >= 3:
        best_length = candidates[0]
        max_divisible = 0
        for candidate in candidates[:min(5, len(candidates))]:  # Check first few candidates
            divisible_count = sum(1 for c in candidates if c % candidate == 0)
            if divisible_count > max_divisible:
                max_divisible = divisible_count
                best_length = candidate
        length = best_length
    elif len(candidates) > 0:
        # Just use the first candidate
        length = candidates[0]
    else:
        # Fall back to old jump method
        diff = [0]
        for i in range(19):
            diff.append(s[i+1]/s[i])
        max1 = max2 = max3 = 0
        # Store the largest jump in diff into max1 and its key length into i1
        for i in range(20):
            if diff[i] > max1:
                max1 = diff[i]
                i1 = i + 1
        # Store the 2nd largest jump in diff into max2 and its key length into i2
        for i in range(20):
            if diff[i] > max2 and diff[i] != max1:
                max2 = diff[i]
                i2 = i + 1
        # Store the 3rd largest jump in diff into max3 and its key length into i3
        for i in range(20):
            if diff[i] > max3 and diff[i] != max1 and diff[i] != max2:
                max3 = diff[i]
                i3 = i + 1
        # Compute gcd of the three key lengths to get the final key length
        length = math.gcd(i1, i2) # In this example, 12 and 6 -> gcd = 6
        length = math.gcd(length, i3) # In this example, 6 and 18 -> gcd = 6

    print(f"\nDetected key length: {length}\n")
            
	# Extract length sequences and, for each one, brute-force the shift key
    key = []
    for k in range(length):
        tmp = []
        for i in range(k,len(ct),length):
            # Extract every length-th letter starting from position k. 
            # E.g. k=0, length=6 (key length) -> positions 0, 6, 12, 18, ...
            # E.g. k=5, length=6 (key length) -> positions 5, 11, 17, 23, ...
            tmp.append(ct[i]) 
        key.append(get_key_shift(tmp))

    # Decrypt the ciphertext, where the i-th character is shifted by key[i%length] positions
    pt = list(ct) # Convert ciphertext string to list for mutability
    for i in range(len(pt)):
        # Refer to ASCII table
        # e.g. O: (89 - 65 - key[0%6]) % 26 + 97
        # e.g. O: (24 - key) % 26 + 97
        pt[i] = chr((ord(pt[i]) - ord('A') - key[i%length]) % 26 + ord('a'))

    # Print plaintext and key
    pt = "".join(pt) # Convert list back to string
    print (f"Plaintext:\n{pt}")
    # Convert each key shift value back to character
    for i in range(length):
        key[i] = chr(key[i] + ord('A'))
    key = "".join(key) # Convert list to string
    print (f"Key: {key}")


if __name__ == "__main__":
    main()	