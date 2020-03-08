# -*- coding: utf-8 -*-

""" Симметричные методы шифрования.
Реализуйте алгоритм IDEA шифрования и дешифрования текста произвольной длины
    с режимом шифрования СBC.
Вектор инициализации для осуществления шифрования и дешифрования текста
    задайте самостоятельно."""

import copy
import pickle
from itertools import cycle, zip_longest, islice


class IDEA:
    def __init__(self, key):
        self.__NUM_ROUNDS = 8
        self.__key = self.__set_key(key)

    def __set_key(self, key):
        key = hex(key)[2:]
        len_hex_key = len(key)
        subkey = [0] * 16
        idx = 0
        for beg in range(0, len_hex_key, 2):
            if idx >= 16:
                raise Exception('idx >= 16')
            end = beg + 2
            if end > len_hex_key:
                end -= (end - len_hex_key)
            subkey[idx] = int('0x{}'.format(key[beg:end]), 16)
            idx += 1
        return subkey

    def __convert_base(self, num, to_base=10, from_base=10):
        if isinstance(num, str):
            n = int(num, from_base)
        else:
            n = int(num)
        alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        if n < to_base:
            return alphabet[n]
        else:
            return self.__convert_base(n // to_base, to_base) + alphabet[n % to_base]

    def __text_to_bits(self, text):
        bits = bin(int.from_bytes(text.encode(), 'big'))[2:]
        return bits.zfill(8 * ((len(bits) + 7) // 8))

    def __text_from_bits(self, bits):
        n = int(bits, 2)
        return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode() or '\0'

    def __add(self, x, y):
        assert 0 <= x <= 0xFFFF
        assert 0 <= y <= 0xFFFF
        return (x + y) & 0xFFFF

    def __multiply(self, x, y):
        assert 0 <= x <= 0xFFFF
        assert 0 <= y <= 0xFFFF
        if x == 0x0000:
            x = 0x10000
        if y == 0x0000:
            y = 0x10000
        z = (x * y) % 0x10001
        if z == 0x10000:
            z = 0x0000
        assert 0 <= z <= 0xFFFF
        return z

    def __negate(self, x):
        assert 0 <= x <= 0xFFFF
        return (-x) & 0xFFFF

    def __reciprocal(self, x):
        assert 0 <= x <= 0xFFFF
        if x == 0:
            return 0
        else:
            return pow(x, 0xFFFF, 0x10001)

    def __bytelist_to_debugstr(self, bytelist):
        assert isinstance(bytelist, (list, tuple))
        return "[" + " ".join("{}".format(b) for b in bytelist) + "]"

    def encrypt(self, block, printdebug=False):
        return self.__crypt(block, self.__key, "encrypt", printdebug)

    def decrypt(self, block, printdebug=False):
        return self.__crypt(block, self.__key, "decrypt", printdebug)

    def __crypt(self, block, key, direction, printdebug):
        keyschedule = self.__expand_key_schedule(key)
        if direction == "decrypt":
            keyschedule = self.__invert_key_schedule(keyschedule)
        w = int(block[0]) << 8 | int(block[1])
        x = int(block[2]) << 8 | int(block[3])
        y = int(block[4]) << 8 | int(block[5])
        z = int(block[6]) << 8 | int(block[7])
        for i in range(self.__NUM_ROUNDS):
            j = i * 6
            w = self.__multiply(w, keyschedule[j + 0])
            x = self.__add(x, keyschedule[j + 1])
            y = self.__add(y, keyschedule[j + 2])
            z = self.__multiply(z, keyschedule[j + 3])
            u = self.__multiply(w ^ y, keyschedule[j + 4])
            v = self.__multiply(self.__add(x ^ z, u), keyschedule[j + 5])
            u = self.__add(u, v)
            w ^= v
            x ^= u
            y ^= v
            z ^= u
            x, y = y, x
        x, y = y, x
        w = self.__multiply(w, keyschedule[-4])
        x = self.__add(x, keyschedule[-3])
        y = self.__add(y, keyschedule[-2])
        z = self.__multiply(z, keyschedule[-1])
        return [w >> 8, w & 0xFF, x >> 8, x & 0xFF, y >> 8, y & 0xFF, z >> 8, z & 0xFF]

    def __expand_key_schedule(self, key):
        bigkey = 0
        for b in key:
            assert 0 <= int(b) <= 255
            bigkey = (bigkey << 8) | int(b)
        assert 0 <= bigkey < (1 << 128)
        bigkey = (bigkey << 16) | (bigkey >> 112)
        result = []
        for i in range(self.__NUM_ROUNDS * 6 + 4):
            offset = (i * 16 + i // 8 * 25) % 128
            result.append((bigkey >> (128 - offset)) & 0xFFFF)
        return tuple(result)

    def __invert_key_schedule(self, keysch):
        assert isinstance(keysch, tuple) and len(keysch) % 6 == 4
        result = []
        result.append(self.__reciprocal(keysch[-4]))
        result.append(self.__negate(keysch[-3]))
        result.append(self.__negate(keysch[-2]))
        result.append(self.__reciprocal(keysch[-1]))
        result.append(keysch[-6])
        result.append(keysch[-5])
        for i in range(1, self.__NUM_ROUNDS):
            j = i * 6
            result.append(self.__reciprocal(keysch[-j - 4]))
            result.append(self.__negate(keysch[-j - 2]))
            result.append(self.__negate(keysch[-j - 3]))
            result.append(self.__reciprocal(keysch[-j - 1]))
            result.append(keysch[-j - 6])
            result.append(keysch[-j - 5])
        result.append(self.__reciprocal(keysch[0]))
        result.append(self.__negate(keysch[1]))
        result.append(self.__negate(keysch[2]))
        result.append(self.__reciprocal(keysch[3]))
        return tuple(result)


class CBC:
    def __init__(self, file_name, init_vector=None):
        if init_vector is None:
            self.__INIT_VECTOR = 'this is initialization vector'
        else:
            self.__INIT_VECTOR = copy.deepcopy(init_vector)
        self.__file_name = '{}.pkl'.format(file_name)
        self.__count = 0
        # Было ли чтение файла
        self.__WAS_INPUT = True
        self.__WAS_NOT_INPUT = not self.__WAS_INPUT

    def __encryptXOR(self, key, text):
        ''' Шифрование гаммированием '''
        return [(m ^ k) for m, k in islice(zip_longest(text, cycle(key)), len(text))]

    def __split_to_chr_8(self, text):
        """Разбивает строку на блоки по 8 символов"""
        blocks = []
        size_block = 8
        length = len(text)
        for beg in range(0, length, size_block):
            end = beg + size_block
            if end > length:
                end -= (end - length)
            blocks.append([ord(x) for x in text[beg:end]])
        return blocks

    def __encrypt(self, algorithm: IDEA, text):
        data = [{'input': self.__WAS_NOT_INPUT, 'count': 0}, self.__INIT_VECTOR]
        try:  # Попытаться открыть файл
            with open(self.__file_name, 'rb') as file:
                try:  # Попытаться читать
                    data = pickle.load(file)
                except pickle.UnpicklingError as exp:
                    raise exp
        except FileNotFoundError:
            with open(self.__file_name, 'wb') as file:
                pickle.dump(data, file)
        len_text = len(text)
        while len_text < 8:
            len_text += 1
            text.append(0)
            data[0]['count'] += 1
        # XOR
        key = [ord(x) for x in data[-1]]
        res = self.__encryptXOR(key, text)
        # Процедура шифрования
        res = algorithm.encrypt(res)
        res = ''.join([chr(x) for x in res])
        data.append(res)
        with open(self.__file_name, 'wb') as file:
            pickle.dump(data, file)

    def encrypt(self, algorithm: IDEA, text):
        for chunk in self.__split_to_chr_8(text):
            self.__encrypt(algorithm, chunk)

    def __decrypt(self, algorithm: IDEA):
        data = None
        try:  # Попытаться открыть файл
            with open(self.__file_name, 'rb') as file:
                try:  # Попытаться читать
                    data = pickle.load(file)
                    if self.__len_data == 2:
                        raise Exception('{} is empty'.format(self.__file_name))
                except pickle.UnpicklingError as exp:
                    raise exp
        except FileNotFoundError as exp:
            raise exp
        key, text = None, None
        if data[0]['input'] == self.__WAS_NOT_INPUT:
            key, text = data[1], data[2]
            data[0]['input'] = self.__WAS_INPUT
        elif data[0]['input'] == self.__WAS_INPUT:
            if self.__len_data > 4:
                key, text = data.pop(2), data[2]
                data.append(key)
                self.__len_data -= 1
            elif self.__len_data == 4:
                key, text = data.pop(2), data.pop(2)
                data.append(key)
                data.append(text)
                self.__len_data -= 2
                data[0]['input'] = self.__WAS_NOT_INPUT
        key = [ord(x) for x in key]
        text = [ord(x) for x in text]
        text = algorithm.decrypt(text)
        text = self.__encryptXOR(key, text)
        with open(self.__file_name, 'wb') as file:
            pickle.dump(data, file)
        return ''.join(chr(x) for x in text)

    def decrypt(self, algorithm: IDEA):
	"""Дешифрование"""
        self.__len_data = len(pickle.load(open(self.__file_name, 'rb')))
        text = ''
        try:
            while True:
                text += self.__decrypt(algorithm)
        except Exception:
            pass
        return text


def main():
    key = 0x2BD6459F82C5B300952C49104881FF48  # 16 byte (128 bit)
    my_IDEA = IDEA(key)

    # Читать текст из файла
    text = open('input.txt', 'r').read()

    # Шифрование
    cbc = CBC('encrypt')
    cbc.encrypt(my_IDEA, text)

    # Дешифрование
    open('output.txt', 'w').write(cbc.decrypt(my_IDEA))

if __name__ == '__main__':
    main()
