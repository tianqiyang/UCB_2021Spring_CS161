from helpers import PKCS7_pad, PKCS7_unpad, valid_pad, permute, D, xor_block, CBC_encrypt, CBC_decrypt, sha256

def test1(invalid_last_byte):
    msg = b"TITLE: Company-wide implementation of zero food waste policy"
    padded_msg = PKCS7_pad(msg)

    if not (type(invalid_last_byte) == int):
        print('`invalid_last_byte` must be a number')
        return

    invalid_msg = bytearray(padded_msg)
    invalid_msg[-1] = invalid_last_byte

    if valid_pad(bytes(invalid_msg)):
        print('`invalid_msg` should have invalid padding')
        return
    print('All tests passed!')


def test2(valid_last_byte_1, valid_last_byte_2):
    msg = b"As part of our ongoing environmental initiative, we are switching our canteens to zero food waste operation."
    padded_msg = PKCS7_pad(msg)

    if not (type(valid_last_byte_1) == int and type(valid_last_byte_2) == int):
        print('Your valid bytes must be integers!')
        return

    valid_msg_1 = bytearray(padded_msg)
    valid_msg_1[-1] = valid_last_byte_1

    valid_msg_2 = bytearray(padded_msg)
    valid_msg_2[-1] = valid_last_byte_2

    if not (1 <= valid_last_byte_1 <= 16 and 1 <= valid_last_byte_2 <= 16):
        print('Your valid bytes must be in the range [1, 16]')
        return

    if valid_last_byte_1 == valid_last_byte_2:
        print('Your valid bytes must be different from each other.')
        return

    if not valid_pad(bytes(valid_msg_1)):
        print('`valid_last_byte_1` did not result in valid padding!')
        return
    if not valid_pad(bytes(valid_msg_2)):
        print('`valid_last_byte_2` did not result in valid padding!')
        return

    print('All tests passed!')


def test3(fn):
    iv = b'\xa3%P\xa6\xed\xba\x978$\xe2D\xe9\x89!\xe15'
    ct = b'\xb7\x16\xaf\xc2]\xe7\x86\x14\x084\xe5\x97\xc9\xfc\x8e\xcb\xe4:n\xa6\xd5z\xfaR\xef\x96\xffs>\xc6+\x8f'
    C0 = iv
    C1 = ct[:16]
    C2 = ct[16:]
    pthash = b'2\x7f]\xbaC\xe4\xdd]K\x1c!\xf9\xa5\xc0(5\xc3\xd4Y0\x9d\xb3\xca\xef*\xb0\xde$\xa0\x84M8'
    P = fn(D, C1, C0) + fn(D, C2, C1)
    if sha256(PKCS7_unpad(bytes(P))) != pthash:
        print('Message did not decrypt correctly')
        return

    print('All tests passed!')
    story = "Given the overwhelming success of this policy at HQ, we are excited to expand our ongoing commitment."
    print('[storyline message] ' + story)
    # are you ready for the truth, curious one?
    # secret_key = b'\xfa\x17Y\xc0\x08~(b\xec=\xce\xd5\x19N\x03;\xcab\xc7\xe3\x11\xaa\x8ct\xc4\xc4\x02\x7f\xcf)g\x08'
    # secret_ct = b'\xcft\xa1UQ\xc4\x1a\x83v\xa1NF\xf6\x13f[\xd7:3\xd2\xe1\xa1\xc1*\xb2\x80\x82\xd0\x9dVc\x99'
    # print(CBC_decrypt((iv, secret_ct), secret_key))


def test4(pad_fn):
    ct = b'\x9e\xfd\x03\xd2\xdb\xd4\xcfC\x94P\xe4\xae\xf6\x9c\xa4\xffw\x994\x11\x8b\xfb\x82\x90\xb9\x1eA\xbb\xb0\x1e`\x11'
    C1 = bytearray(ct[:16])
    C2 = bytearray(ct[16:])
    C1[-1] = pad_fn(D(C2)[-1])

    if not valid_pad(bytes(xor_block(C1, D(C2)))):
        print('The generated padding is not valid.')
        return
    if not valid_pad(bytes(xor_block(permute(C1, 15), D(C2)))):
        print('The last byte should guarantee correct padding even if the first 15 bytes of the message change!')
        return

    print('All tests passed!')
    story = "As the policy name suggests, no food waste is allowed in both cooking and dining facilities."
    print('[storyline message] ' + story)
    # iv = b'\xa3%P\xa6\xed\xba\x978$\xe2D\xe9\x89!\xe15'
    # secret_key = b'\xfa\x17Y\xc0\x08~(b\xec=\xce\xd5\x19N\x03;\xcab\xc7\xe3\x11\xaa\x8ct\xc4\xc4\x02\x7f\xcf)g\x08'
    # print(CBC_decrypt((iv, ct), secret_key))

def test5(decode_fn, pad_fn):
    msg = b'oski is terrifying'
    msg_padded = b'oski is terrifying\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'
    ct = b'\xc9\xb9zx\xccQ\x01\xed\xcf\x0ff\x93\x13\xfe`\xac\x1c\x10:\xe6|T\xe6\xb4JV\xe4\x8e\xe0\x02g\xe7'
    C1 = bytearray(ct[:16])
    C2 = bytearray(ct[16:])
    C1[-1] = pad_fn(D(C2)[-1])
    
    if decode_fn(ct[15], C1[-1]) != msg_padded[31]:
        print('The correct byte was not recovered')
        return
    
    print('All tests passed!')
    story = "To enforce this policy, we are removing all trash cans from the kitchen and the dining hall."
    print('[storyline message] ' + story)
    return
    

def test6(decryption_fn):
    pt = b'oski is terrifying\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'
    ct = b'\xc9\xb9zx\xccQ\x01\xed\xcf\x0ff\x93\x13\xfe`\xac\x1c\x10:\xe6|T\xe6\xb4JV\xe4\x8e\xe0\x02g\xe7'
    C1 = ct[:16]
    C2 = ct[16:]
    print(pt[31])
    def oracle(C_last, C):
        return valid_pad(bytes(xor_block(D(C), C_last)))
    
    if not decryption_fn(C1, C2, oracle) == pt[31]:
        print('Last byte was not correct.')
        return
    
    print('All tests passed!')
    story = "Please prepare to adjust your operations accordingly."
    print('[storyline message] ' + story)


def test7(decryption_fn):
    iv = b'\xa3%P\xa6\xed\xba\x978$\xe2D\xe9\x89!\xe15'
    pt = b'oski is terrifying\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'
    ct = b'\xc9\xb9zx\xccQ\x01\xed\xcf\x0ff\x93\x13\xfe`\xac\x1c\x10:\xe6|T\xe6\xb4JV\xe4\x8e\xe0\x02g\xe7'
    C0 = b'\xa3%P\xa6\xed\xba\x978$\xe2D\xe9\x89!\xe15'
    C1 = ct[:16]
    C2 = ct[16:]
    key = b'\xfa\x17Y\xc0\x08~(b\xec=\xce\xd5\x19N\x03;\xcab\xc7\xe3\x11\xaa\x8ct\xc4\xc4\x02\x7f\xcf)g\x08'
    
    def oracle(C_last, C):
        return valid_pad(bytes(xor_block(D(C), C_last)))
    
    if not bytes(decryption_fn(C1, C2, oracle)) == pt[16:]:
        print('Second block did not decrypt correctly.')
        print(f'You gave me {bytes(decryption_fn(C1, C2, oracle))}, but I expected {pt[16:]}')
        return
    if not bytes(decryption_fn(C0, C1, oracle)) == pt[:16]:
        print('First block did not decrypt correctly.')
        print(f'You gave me {bytes(decryption_fn(C0, C1, oracle))}, but I expected {pt[:16]}')
        return
    
    print('All tests passed!')
    story = "Signed, CSA HQ."
    print('[storyline message] ' + story)
