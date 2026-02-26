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
        q.append(ct.count(letter))
    for i in range(26):
        q[i] /= len(ct)

    # Compute index of coincidence for different shift values j
    # Key value is maintained into variable key (max IOC)
    max_ioc = 0
    for j in range(26):
        ioc = 0.0
        for i in range(26):
            ioc += p[i]*q[(i+j)%26]

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
    	print (f"Error: can\'t open file {sys.argv[1]}")
    	sys.exit()

    # Read ciphertext into string ct and convert to uppercase
    ct = file.read()
    ct = ct.upper()
	
	# Compute index of coincidence for different key lengths k (from 1 to 20)
    s = []
    tmp = []
    q = list(range(26))
    for k in range(1,21,1):
        # Set all frequencies to 0
        for i in range(26):
        	q[i] = 0.0

        # Extract ciphertext at positions 0, k, 2k, 3k, ...
        # Store it in list tmp
        tmp.clear()
        for i in range(0,len(ct),k):
        	tmp.append(ct[i])

        # Compute character frequencies for ciphertext tmp (array q)
        # Compute counts then divide by len(tmp)
        for i in range(len(tmp)):
        	q[ord(tmp[i])-ord('A')] = q[ord(tmp[i])-ord('A')] + 1
        for i in range(26):
        	q[i] /= len(tmp)

        # Compute index of coincidence and store it into list s
        ioc = 0.0;
        for i in range(26):
        	ioc += q[i] * q[i]
        s.append(ioc)
        
    for i in range(20):
        print(f"{i}: {s[i]}")
	
    # Compute the three largest jumps in list s and then get their gcd
	# This will be the key length (might not always work)
    diff = [0]
    for i in range(19):
        diff.append(s[i+1]/s[i])
    max1 = max2 = max3 = 0
    for i in range(20):
        if diff[i] > max1:
            max1 = diff[i]
            i1 = i + 1
    for i in range(20):
        if diff[i] > max2 and diff[i] != max1:
            max2 = diff[i]
            i2 = i + 1
    for i in range(20):
        if diff[i] > max3 and diff[i] != max1 and diff[i] != max2:
            max3 = diff[i]
            i3 = i + 1
    length = math.gcd(i1, i2)
    length = math.gcd(length, i3)
            
	# Extract length sequences and, for each one, brute-force the shift key
    key = []
    for k in range(length):
        tmp = []
        for i in range(k,len(ct),length):
            tmp.append(ct[i])
        key.append(get_key_shift(tmp))

    # Decrypt the ciphertext, where the i-th character is shifted by key[i%length] positions
    pt = list(ct)
    for i in range(len(pt)):
    	pt[i] = chr((ord(pt[i]) - ord('A') - key[i%length]) % 26 + ord('a'))

    # Print plaitext and key
    pt = "".join(pt)
    print (f"Plaintext:\n{pt}")
    for i in range(length):
    	key[i] = chr(key[i] + ord('A'))
    key = "".join(key)
    print (f"Key: {key}")


if __name__ == "__main__":
    main()	