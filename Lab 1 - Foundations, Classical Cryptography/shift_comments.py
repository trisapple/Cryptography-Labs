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
	q.append(ct.count(letter)) # Count of each letter in an array from A to Z e.g. [34, 18, 1, 30, 39, 50, 8, 2, 5, 2, 12, 0, 42, 4, 24, 15, 54, 11, 8, 23, 37, 0, 3, 14, 13, 35]
for i in range(26):
	q[i] /= len(ct) # Divide each count by total length of ciphertext to get frequency [0.07024793388429752, 0.0371900826446281, ...]

# Compute index of coincidence for different shift values j
# Key value is maintained into variable key (stores the max IOC)
max_ioc = 0
for j in range(26):
    ioc = 0.0
    for i in range(26):
        ioc += p[i]*q[(i+j)%26] # Statistical Attack Method, refer to 1.2 Notes

    print (f"{j}: {ioc}")
	# Store the maximum IOC and corresponding key
    if ioc > max_ioc:
        max_ioc = ioc
        key = j

# Decrypt ciphertext by subtracting key
pt = list(ct) # Convert ciphertext string to list for mutability e.g. ['O', 'D', 'K', 'B', ...]
for i in range(len(pt)):
	# Refer to ASCII table
	# e.g. O: (79 - 65 - key) % 26 + 97
	# e.g. O: (14 - key) % 26 + 97
	pt[i] = chr((ord(pt[i]) - ord('A') - key) % 26 + ord('a')) 
	
# Print plaintext and key
pt = "".join(pt) # Convert list back to string
k = chr(key + ord('A')) # Convert key shift value back to character
print (f"\nPlaintext:\n{pt}")
print (f"The key is: {k}")
