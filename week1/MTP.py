from itertools import combinations
from collections import Counter

def decrypt(ciphers):
    """
    Takes a list of hexadecimal formatted ciphertexts and returns their 
    plaintexts up to the column index of the shortest text.
    """
    bcs = [bytes.fromhex(cipher) for cipher in ciphers]
    key = get_key(bcs)
    pts = ["".join(chr(b) for b in xor(key, bc)) for bc in bcs]
    
    [print(f"Text #{num + 1}:\n{pt}\n") for num, pt in enumerate(pts)]
    return pts

#### HELPER FUNCTIONS ####
def get_key(ciphers):
    """
    Takes a list of bytestring formatted ciphertexts. If the texts were 
    encrypted with the same One-Time-Pad, computes and returns key values up to 
    the length of the shortest ciphertext. 
    """
    def get_keyval(col):
        """
        Gets a key value at the specified column index
        """
        key_letters = Counter()
        # create a counter to tally possible key letters
        for c1, c2 in combinations(ciphers, 2):
        # get every possible pair of ciphertexts
            if chr(c1[col]^c2[col]).isalpha():
            # xor the pair of ct chars at the current col and check if letter:
            #   (p1[i] xor  k[i]) xor (p2[i]  xor k[i]) == p1[i] xor p2[i]
            # if p1[i] xor p2[i]  in {A-Za-z} => p1[i]  ==   ' ' ||  p2[i] == ' '
            # and k[i] ==   c[i]  xor p[i]
            # so  k[i] ==  c1[i]  xor ' ' || c2[i] xor ' '
                key_letters.update({c1[col]^32: 1, c2[col]^32: 1}) 
                # xor each c with space to get possible key chars and count both
                # note: key chars are inverted case of the ciphertext chars
                # only p chars that are spaces will get most votes: the corresponding
        return key_letters.most_common(1)[0][0]
        
    return [get_keyval(col) for col in range(min(len(c) for c in ciphers))]

def xor(bs1, bs2):
    """
    XOR's the bytes of two bytestrings up to the shortest length
    """
    return [b1^b2 for b1, b2 in zip(bs1, bs2)]

#### TEST CODE ####
CIPHERS = [cipher.strip() for cipher in open('ciphers.txt')]
decrypt(CIPHERS)

#### NOTES ####
# Binary Values
# {A-Z}: 010.....
# {a-z}: 011.....
# ' '  : 001.....

# XOR Combinations
# {A-Z} xor ' '   == 011..... ({a-z})
# {a-z} xor ' '   == 010..... ({A-Z})
# {A-Z} xor {a-z} == 001..... (' ')

# if x xor y in {A-Za-z} then x == ' ' || y == ' '