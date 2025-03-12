from Crypto.Cipher import AES
from base64 import b64encode
from Crypto.Util.Padding import pad
import random
import json
import requests
import base64

headers = {
			'Accept': '*/*',
			'Accept-Encoding': 'gzip,deflate,sdch',
			'Accept-Language': 'zh-CN,zh;q=0.8,gl;q=0.6,zh-TW;q=0.4',
			'Connection': 'keep-alive',
			'Content-Type': 'application/x-www-form-urlencoded',
			'Host': 'music.163.com',
			'Referer': 'https://music.163.com/',
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36'
		}

def gen_ran_string(num=16):
    """
    生成随机密钥
    :param num: =16
    :return: 16位随机字符串
    """
    chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    result = ""
    b_len = len(chars)
    for _ in range(num):
        index = int(random.random() * b_len)
        result += chars[index]
    return result

class RSAKeyPair:
    def __init__(self, e_hex, d_hex, m_hex):
        self.e = int(e_hex, 16)
        self.m = int(m_hex, 16)
        # 计算 chunk_size：根据模数字节长度确定
        byte_length = (self.m.bit_length() + 7) // 8
        self.chunk_size = byte_length - 2  # 等效于原JS的 2 * biHighIndex(m)
        self.radix = 16

def encrypted_string(rsa_key, s):
    # 将字符串编码为Latin-1字节数组
    byte_data = s.encode('latin-1')
    # 填充0直到长度为chunk_size的倍数
    padding = (-len(byte_data)) % rsa_key.chunk_size
    byte_data += bytes(padding)

    encrypted_blocks = []
    hex_length = (rsa_key.m.bit_length() + 3) // 4  # 模数的十六进制长度

    for i in range(0, len(byte_data), rsa_key.chunk_size):
        chunk = byte_data[i:i + rsa_key.chunk_size]
        # 转换为小端整数
        chunk_int = int.from_bytes(chunk, byteorder='little')
        # RSA加密：计算 (chunk^e) mod m
        encrypted_int = pow(chunk_int, rsa_key.e, rsa_key.m)
        # 转换为固定长度的十六进制字符串
        encrypted_hex = format(encrypted_int, '0{}x'.format(hex_length))
        encrypted_blocks.append(encrypted_hex)

    return ' '.join(encrypted_blocks)


def rsa(a, e_hex, m_hex):
    rsa_key = RSAKeyPair(e_hex, "", m_hex)
    return encrypted_string(rsa_key, a)

def post_request(url,params):
    session = requests.Session()
    res=session.post(url=url,headers=headers,data=params)
    return res.json()

def aes_cbc_encrypt(plaintext: str, key: bytes, iv: bytes) -> bytes:
    """
    AES-CBC加密
    :param plaintext: 明文（字符串）
    :param key: 密钥（16/24/32字节）
    :param iv: 初始化向量（16字节）
    :return: Base64编码的密文字符串
    """
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    return base64.b64encode(ciphertext)

def encrypt_data(id):
    ramdom_string = gen_ran_string()
    params = {
        'ids': [id],
        'csrf_token': '',
        'encodeType': 'aac',
        'level': 'standard'
    }
    e = '010001'
    f = '00e0b509f6259df8642dbc35662901477df22677ec152b5ff68ace615bb7b725152b3ab17a876aea8a5aa76d2e417629ec4ee341f56135fccf695280104e0312ecbda92557c93870114af6c9d05c4f7f0c3685b7a46bee255932575cce10b424d813cfe4875d3e82047b97ddef52741d546b8e289dc6935b3ece0462db0a22b8e7'
    key = b'0CoJUm6Qyw8W8jud'
    iv = b'0102030405060708'
    encText=aes_cbc_encrypt(json.dumps(params),key,iv)
    encText = aes_cbc_encrypt(encText.decode('utf-8'), ramdom_string.encode('utf-8'), iv)
    encText=encText.decode('utf-8')
    encSecKey = rsa(ramdom_string, e, f)
    data = {
        'params': encText,
        'encSecKey': encSecKey
    }
    return data

def get_song_by_songId(id):
    data=encrypt_data(id)
    res=post_request('https://music.163.com/weapi/song/enhance/player/url/v1',data)
    print(res)
    return res

if __name__ == '__main__':
    id='412902095' #音乐id
    get_song_by_songId(id)
