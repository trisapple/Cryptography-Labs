import sys

# Check whether input file name is provided
if len(sys.argv) < 2:
	print(f"Usage: {sys.argv[0]} input-file\n")
	sys.exit()

# Open file, exit if error
try:
    file = open(sys.argv[1], "r");
except IOError:
	print (f"Error: can\'t open file {sys.argv[1]}\n")
	sys.exit()

# Hardcoded frequencies for English characters
p = [0.082, 0.015, 0.028, 0.042, 0.127, 0.022, 0.020, 0.061, 0.070, 0.001, 0.008, 0.040, 0.024,
	0.067, 0.075, 0.019, 0.001, 0.060, 0.063, 0.090, 0.028, 0.010, 0.024, 0.002, 0.020, 0.001]

# Read ciphertext into string ct and convert to uppercase
ct = file.read()
ct = ct.upper()

# Compute character frequencies for ciphertext ct (array q)
# Compute counts then divide by size
q = []
alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
for letter in alphabet:
	q.append(ct.count(letter))
for i in range(26):
	q[i] /= len(ct)

# Compute index of coincidence for different shift values j
# Key value is maintained into variable key (stores the max IOC)
max = 0
for j in range(26):
    sum = 0.0
    for i in range(26):
        sum += p[i]*q[(i+j)%26]

    print (f"{j}: {sum}")
    if sum > max:
        max = sum
        key = j

# Decrypt ciphertext by subtracting key
pt = list(ct)
for i in range(len(pt)):
	pt[i] = chr((ord(pt[i]) - ord('A') - key) % 26 + ord('a'))

# Print plaintext and key
pt = "".join(pt)
k = chr(key + ord('A'))
print (f"\nPlaintext:\n{pt}")
print (f"The key is: {k}")
