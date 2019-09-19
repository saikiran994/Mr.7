
import os
import sys
import time
import multiprocessing
import hashlib
import binascii
import itertools

MATRIX_SIZE = [3,3]
MAX_LEN = MATRIX_SIZE[0]*MATRIX_SIZE[1]
FOUND = multiprocessing.Event()

def lookup(param):
    global FOUND
    lenhash = param[0]
    target = param[1]
    positions = param[2]

    if FOUND.is_set() is True:
        return None

    # get all possible ways
    perms = itertools.permutations(positions, lenhash)
    
    for item in perms:
        # construct pattren
        if FOUND.is_set() is True:
            return None
        pattern = ''.join(str(v) for v in item)
        # convert the pattern to hex
        key = binascii.unhexlify(''.join('%02x' % (ord(c) - ord('0')) for c in pattern))
        sha1 = hashlib.sha1(key).hexdigest()
        if sha1 == target:
            FOUND.set()
            return pattern
    return None

def show_pattern(pattern):
    """
    Shows the pattern "graphically"
    """

    gesture = [None, None, None, None, None, None, None, None, None]

    cont = 1
    for i in pattern:
        gesture[int(i)] = cont
        cont += 1

    print "[+] Gesture:\n"

    for i in range(0, 3):
        val = [None, None, None]
        for j in range(0, 3):
            val[j] = " " if gesture[i * 3 + j] is None else str(gesture[i * 3 + j])

        print '  -----  -----  -----'
        print '  | %s |  | %s |  | %s |  ' % (val[0], val[1], val[2])
        print '  -----  -----  -----'

def crack(target_hash):
    ncores = multiprocessing.cpu_count()
    pool = multiprocessing.Pool(ncores)
    # generates the matrix positions IDs
    positions = []
    for i in range(0,MAX_LEN):
        positions.append(i)
    
    # sets the length for each worker
    params = []
    count = 1
    for i in range(0,MAX_LEN):
        params.append([count,target_hash,positions])
        count += 1
    
    result = pool.map(lookup,params)
    pool.close()
    pool.join()
    
    ret = None
    for r in result:
        if r is not None:
            ret = r
            break
    return ret

def main():
    print ''
    print '###############################################'
    print '#      Android Pattern UnLocker               #'
    print '#                                             #'
    print '# --------------------------------------------#'
    print '#        Written by techsaikiran              #'
    print '#   ------------------------------------------#'
    print '#                                             #'
    print '# Instagram : techsaikiran                    #'
    print '# https://securityhackingebooks.blogspot.com  #'
    print '# Telegram: https://t.me/HackLikeStar         #'
    print '###############################################\n'

    print '[i] cracking-the-pattern-lock-on-android/\n'
    
    if len(sys.argv) != 2:
        print '[+] Usage: %s /path/to/gesture.key\n' % sys.argv[0]
        sys.exit(0)
    
    if not os.path.isfile(sys.argv[1]):
        print "[e] Cannot access to %s file\n" % sys.argv[1]
        sys.exit(-1)
        
    f = open(sys.argv[1], 'rb')
    gest = f.read(hashlib.sha1().digest_size).encode('hex')
    f.close()

    if len(gest) / 2 != hashlib.sha1().digest_size:
        print "[e] Invalid gesture file?\n"
        sys.exit(-2)

    t0 = time.time()
    pattern = crack(gest)
    t1 = time.time()

    if pattern is None:
        print "[:(] The pattern was not found..."
        rcode = -1
    else:
        print "[:D] The pattern has been FOUND!!! => %s\n" % pattern
        show_pattern(pattern)
        print ""
        print "It took: %.4f seconds" % (t1-t0)
        rcode = 0

    sys.exit(rcode)

if __name__ == "__main__":
    main()
    
