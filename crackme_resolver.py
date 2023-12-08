import random
import hashlib
import string

class CrackmeResolver:

    def generate_serial(self, email: str):
        '''Generate serial for email
        Input:
            email: str - email for crackme
        Output:
            pair of email, serial
        '''

        # A-Z_a-z_0-9 + special symbols true -> other to black symbols list
        black_symbols = [i for i in range(0x20)]
        black_symbols += [i for i in range(0x7f, 0x100, 1)]
        for char in email.encode('cp1251'):
            if char in black_symbols:
                print("[-] Fail \n\t name contain blocked symbol:", hex(char))
                return
        
        #serial_size^2 - 24 mod 1000 == 0 [0x00402E40:0x00402E50]
        #serial size = (2^5)^2 => (0x20) 32 bytes
        serial_length = 0x20

        #email_md5_hash + serial = zeronights_hash => serial = zeronights_hash - email_md5_hash
        email_hash_md5 = hashlib.md5(email.encode('cp1251')).hexdigest()
        zeronights_hash_md5 = hashlib.md5('Z3r0_N1ghts'.encode('cp1251')).hexdigest()
        serial = ""
        for i in range(0, serial_length, 2):
            serial += ''.join('{:02x}'.format((int(zeronights_hash_md5[i] + zeronights_hash_md5[i+1], 16) - int(email_hash_md5[i] + email_hash_md5[i+1], 16)) % 0x100))

        print("[+] Success: \n\temail is: '{}' \n\tserial is: '{}'".format(email, serial))

    def generate_pair(self):
        '''Generate pair email and serial
        Output:
            generated pair of email, serial
        '''

        email = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation) for i in range(random.randint(1,50)))
        
        #serial_size^2 - 24 mod 1000 == 0 [0x00402E40:0x00402E50]
        #serial size = (2^5)^2 => (0x20) 32 bytes
        serial_length = 0x20

        #email_md5_hash + serial = zeronights_hash => serial = zeronights_hash - email_md5_hash
        email_hash_md5 = hashlib.md5(email.encode('cp1251')).hexdigest()
        zeronights_hash_md5 = hashlib.md5('Z3r0_N1ghts'.encode('cp1251')).hexdigest()
        serial = ""
        for i in range(0, serial_length, 2):
            serial += ''.join('{:02x}'.format((int(zeronights_hash_md5[i] + zeronights_hash_md5[i+1], 16) - int(email_hash_md5[i] + email_hash_md5[i+1], 16)) % 0x100))

        print("[+] Success: \n\temail is: '{}' \n\tserial is: '{}'".format(email, serial))

if __name__ == "__main__":
    resolver = CrackmeResolver()
    resolver.generate_serial("Z3r0_N1ghts")
    resolver.generate_serial("info@kaspersky.com")
    resolver.generate_pair()

   