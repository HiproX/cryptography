# -*- coding: utf-8 -*-

""" Полиалфавитный шифр.
Реализуйте программное средство, использующее метод Виженера для шифрования
    и дешифрования текстового документа.
В качестве ключевого слова можно использовать слово произвольной длины
    от 5 до 10 символов."""

tabula_recta = 'abcdefghijklmnopqrstuvwxyz'


def encrypt_vigener(key, text):
    global tabula_recta
    res = []
    count_space = 0
    for idx, ch in enumerate(text):
        if ch != ' ':
            mj = tabula_recta.index(ch)
            kj = tabula_recta.index(key[(idx - count_space) % len(key)])
            res.append(tabula_recta[(mj + kj) % len(tabula_recta)])
        else:
            count_space += 1
            res.append(' ')
    return ''.join(res)


def decrypt_vigener(key, text):
    global tabula_recta
    res = []
    count_space = 0
    for idx, ch in enumerate(text):
        if ch != ' ':
            cj = tabula_recta.index(ch)
            kj = tabula_recta.index(key[(idx - count_space) % len(key)])
            res.append(tabula_recta[(cj - kj) % len(tabula_recta)])
        else:
            count_space += 1
            res.append(' ')
    return ''.join(res)

if __name__ == '__main__':
    key = 'qwerty'
    encrypt_text = encrypt_vigener(key, 'hello world')
    print('Encrypt:', encrypt_text)
    decrypt_text = decrypt_vigener(key, encrypt_text)
    print('\nDecrypt:', decrypt_text)
