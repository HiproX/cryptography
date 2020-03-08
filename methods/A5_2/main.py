# -*- coding: utf-8 -*-

""" Потоковый метод шифрования.
Реализуйте программное средство для поточного шифрования
    текстового файла алгоритмом A5/2.
В качестве примитивных многочленов трех регистров используйте значения:
LFSR №1: x^30 + x^16 + x^15 + x + 1;
LFSR №2: x^38 + x^6 + x^5 + x + 1;
LFSR №3: x^28 + x^3 + 1.
Тактирующий регистр должен быть построен на основе
    образующего многочлена x^17 + x^5 + 1."""


class Generator_A5_2:
    """Генератор A5/2 ключа
При создании объекта обязательно инициализировать регистры R1, R2, R3, R4
    ф-и примитивного многочлена.
Пример инициализации для регистра R1: var.set('R1', [25, 4, 2])
Внимание: ф-я примитивного многочлена для регистра R4 должна действовать
    в диапазоне от 1 до 17."""
    def __init__(self):
        """Конструктор по-умолчанию"""
        self.__data = {
            # polynomial - примитивный многочлен
            # bits - регистр (набор битов)
            # shiftable - разрешение на сдвиг регистра
            # prev_bit - последний бит на выходе регистра
            'R1': {'polynomial': None, 'bits': None, 'shiftable': True, 'prev_bit': None},
            'R2': {'polynomial': None, 'bits': None, 'shiftable': True, 'prev_bit': None},
            'R3': {'polynomial': None, 'bits': None, 'shiftable': True, 'prev_bit': None},
            'R4': {'polynomial': None, 'bits': None, 'shiftable': True, 'prev_bit': None}
        }

    def __getitem__(self, register: str, option: str):
        """Достук к объекту self.__data"""
        assert register in self.__data
        assert option in self.__data[register]
        return self.__data[register][option]

    def __str__(self):
        return '},\n'.join(self.__data.__str__().split('},'))

    def set(self, register: str, polynomial: list):
        """Установить ф-ю примитивного многочлена для регистра 'R1'/'R2'/'R3'/'R4'.
Ф-я должна быть представлена в виде списка/кортежа и включать в себя положительные числа.
Например: [30, 5, 1]
По умолчанию биты значений регистров принимают значение равное единице."""
        assert register in self.__data
        self.__data[register]['polynomial'] = polynomial
        if register != 'R4':
            self.__data[register]['bits'] = [1 for _ in range(max(self.__data[register]['polynomial']))]
        elif register == 'R4':
            for x in polynomial:
                assert x <= 17
            self.__data[register]['bits'] = [1 for _ in range(17)]
        else:
            assert False
        self.__data[register]['prev_bit'] = self.__tact_register(register, max(self.__data[register]['polynomial']))

    def reset(self):
        """Сбросить регистры"""
        for register in self.__data:
            assert self.__data[register]['bits'] is not None
            if register != 'R4':
                self.__data[register]['bits'] = [1 for _ in range(max(self.__data[register]['polynomial']))]
            else:
                self.__data[register]['bits'] = [1 for _ in range(17)]
            self.__data[register]['prev_bit'] = self.__tact_register(register, max(self.__data[register]['polynomial']))

    def __mojority(self, idx_x: int, idx_y: int, idx_z: int):
        """Ф-я управления сдвигами регистров R1, R2, R3.
    idx_x, idx_y, idx_z - биты синхронизации регистра R4."""
        # Извлечение значений из битов синхронизации регистра R4
        x = self.__data['R4']['bits'][idx_x - 1]
        y = self.__data['R4']['bits'][idx_y - 1]
        z = self.__data['R4']['bits'][idx_z - 1]
        # Вычисления
        res = x & y | x & z | y & z
        # Изменение разрешения на сдвиг регистра R1
        if res == self.__data['R4']['bits'][idx_z - 1]:
            self.__data['R1']['shiftable'] = True
        else:
            self.__data['R1']['shiftable'] = False
        # Изменение разрешения на сдвиг регистра R2
        if res == self.__data['R4']['bits'][idx_x - 1]:
            self.__data['R2']['shiftable'] = True
        else:
            self.__data['R2']['shiftable'] = False
        # Изменение разрешения на сдвиг регистра R3
        if res == self.__data['R4']['bits'][idx_y - 1]:
            self.__data['R3']['shiftable'] = True
        else:
            self.__data['R3']['shiftable'] = False
        return res

    def __tact_register(self, register: str, tacts: int = 1):
        """Такт регистра.
    register - регистр для тактирования (R1/R2/R3/R4).
    tacts - кол-во тактов."""
        output = None
        for _ in range(tacts):
            result = 0
            for it in self.__data[register]['polynomial']:
                result ^= self.__data[register]['bits'][it - 1]
            output = self.__data[register]['bits'][-1]  # извлекаем последний бит
            self.__data[register]['bits'] = [result, *self.__data[register]['bits'][:-1]]  # сдвигаем
        return output  # возвращаем бит на выходе

    def tact(self, tacts: int = 1):
        """Тактирование регистров.
    tacts - кол-во тактов."""
        result = None
        for _ in range(tacts):
            self.__mojority(3, 7, 10)
            self.__tact_register('R4')
            result = 0

            for register in self.__data:
                assert self.__data[register]['bits'] is not None
                if register != 'R4':
                    if self.__data[register]['shiftable']:
                        self.__data[register]['prev_bit'] = self.__tact_register(register)
                        result ^= self.__data[register]['prev_bit']
                    else:
                        result ^= self.__data[register]['prev_bit']
        return result

    def generate(self, lenght: int):
        """Генерация ключа A5/2
    length - длина желаемого ключа."""
        return ''.join(str(self.tact()) for _ in range(lenght))


def encryptXOR(key: str, text: str):
    """Шифрование гаммированием"""
    from itertools import cycle, zip_longest, islice
    return ''.join(chr(ord(m) ^ ord(k)) for m, k in islice(zip_longest(text, cycle(key)), len(text)))


def decryptXOR(key: str, text: str):
    """Дешифрование гаммированием"""
    from itertools import cycle, zip_longest, islice
    return ''.join(chr(ord(e) ^ ord(k)) for e, k in islice(zip_longest(text, cycle(key)), len(text)))

if '__main__' == __name__:
    source_text = 'Hello world!'  # исходный текст

    # Инициализация генератора ключа A5/2 ф-ми примитивного многочлена
    generator = Generator_A5_2()
    generator.set('R1', [30, 16, 15, 1])
    generator.set('R2', [38, 6, 5, 1])
    generator.set('R3', [28, 3])
    generator.set('R4', [17, 5])
    # generator.tact(10)

    print('\nGenerator Before:\n{0}\n'.format(generator))
    # Получение сгенерированного ключа A5_2
    key = generator.generate(len(source_text))
    # Шифрование
    cipher_text = encryptXOR(key, source_text)
    # Дешифрование
    decrypted_text = decryptXOR(key, cipher_text)
    print('Key:', key)
    print('Source text:', source_text)
    print('Cipher text:', cipher_text)
    print('Decrypted text:', decrypted_text)
    print('\nGenerator After:\n{0}'.format(generator))
