#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ELF Parser - BSS Section Inspector for STM32
==================================

A Python class for analyzing .bss section in ELF files with DWARF debug information.
Extracts information about variables including addresses, data types and sizes.

Author: Uneld
Date: 28.11.2025
Version: 1.3
License: MIT
"""

from elftools.elf.elffile import ELFFile
import os


class ElfParsingError(Exception):
    """Базовое исключение для ошибок парсинга ELF"""
    pass


class BssInspector:
    def __init__(self, progress_callback=None):
        """
        Инициализация инспектора BSS

        Args:
            progress_callback: функция обратного вызова для прогресса (принимает значение 0-100)
        """
        self.elf_file = None
        self.var_library = {}
        self.pointer_size = 0
        self.seen_addresses = set()
        self.forbidden_types = {
            'array of unknown', 'unknown',
            'array of compound', 'compound',
            'array of pointer', 'pointer',
            'array of unknown_type', 'unknown_type',
            'array of complex', 'complex',
            'struct/class', }
        self.progress_callback = progress_callback

    def _update_progress(self, value):
        """Обновление прогресса через callback"""
        if self.progress_callback and callable(self.progress_callback):
            self.progress_callback(value)

    # ---------- Типы ----------

    def decode_base_type(self, type_die):
        enc_attr = type_die.attributes.get('DW_AT_encoding')
        size_attr = type_die.attributes.get('DW_AT_byte_size')
        if not enc_attr or not size_attr:
            return "unknown", 0

        encoding = enc_attr.value
        size = size_attr.value

        # DWARF encoding table
        if encoding == 0x01:  # DW_ATE_address
            return "pointer", self.pointer_size or size  # STM32: pointer = uint32_t

        elif encoding == 0x02:  # DW_ATE_boolean
            return "uint8_t", size  # STM32: bool = uint8_t

        elif encoding == 0x03:  # DW_ATE_complex_float
            return "complex", size

        elif encoding == 0x04:  # DW_ATE_float
            return {4: "float", 8: "double", 16: "long double"}.get(size, "float"), size

        elif encoding == 0x05:  # DW_ATE_signed
            return {1: "int8_t", 2: "int16_t", 4: "int32_t", 8: "int64_t"}.get(size, "int"), size

        elif encoding == 0x06:  # DW_ATE_signed_char
            return "int8_t", size

        elif encoding == 0x07:  # DW_ATE_unsigned
            return {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}.get(size, "uint"), size

        elif encoding == 0x08:  # DW_ATE_unsigned_char
            return "uint8_t", size

        elif encoding == 0x09:  # DW_ATE_imaginary_float
            return "imaginary", size

        elif encoding == 0x0a:  # DW_ATE_packed_decimal
            return "packed_decimal", size

        elif encoding == 0x0b:  # DW_ATE_numeric_string
            return "numeric_string", size

        elif encoding == 0x0c:  # DW_ATE_edited
            return "edited", size

        elif encoding == 0x0d:  # DW_ATE_signed_fixed
            return "signed_fixed", size

        elif encoding == 0x0e:  # DW_ATE_unsigned_fixed
            return "unsigned_fixed", size

        elif encoding == 0x0f:  # DW_ATE_decimal_float
            return "decimal_float", size

        return "unknown", size

    def unwrap_qualifiers(self, dwarf_info, type_die, cu_offset):
        # Снимаем volatile/const/restrict/typedef рекурсивно
        while type_die and type_die.tag in (
                'DW_TAG_volatile_type', 'DW_TAG_const_type', 'DW_TAG_restrict_type', 'DW_TAG_typedef'
        ):
            at_type = type_die.attributes.get('DW_AT_type')
            if not at_type:
                break
            ref = at_type.value + cu_offset
            type_die = dwarf_info.get_DIE_from_refaddr(ref)
        return type_die

    def get_array_size(self, array_die, dwarf_info, cu_offset):
        """
        Вычисляет размер массива в байтах на основе поддиапазонов.
        """
        total_elements = 1
        element_size = 0

        # Получаем тип элемента массива
        at_type = array_die.attributes.get('DW_AT_type')
        if at_type:
            elem_die = dwarf_info.get_DIE_from_refaddr(at_type.value + cu_offset)
            _, elem_size, _, _ = self.resolve_type(dwarf_info, elem_die, cu_offset)
            element_size = elem_size

        # Ищем поддиапазоны (DW_TAG_subrange_type)
        for child in array_die.iter_children():
            if child.tag == 'DW_TAG_subrange_type':
                # Получаем количество элементов
                count_attr = child.attributes.get('DW_AT_count')
                upper_bound_attr = child.attributes.get('DW_AT_upper_bound')

                if count_attr:
                    total_elements *= count_attr.value
                elif upper_bound_attr:
                    # Если указана верхняя граница, нужно также получить нижнюю
                    lower_bound_attr = child.attributes.get('DW_AT_lower_bound')
                    lower_bound = lower_bound_attr.value if lower_bound_attr else 0
                    total_elements *= (upper_bound_attr.value - lower_bound + 1)

        return total_elements * element_size if element_size > 0 else 0

    def resolve_type(self, dwarf_info, type_die, cu_offset):
        """
        Возвращает (тип_строкой, размер_в_байтах, final_die, kind)
        - тип_строкой: 'uint32_t', 'pointer', 'array', 'unknown'
        - size: размер этого типа (для pointer — self.pointer_size; array — 0)
        - final_die: последний DIE после распаковки
        - kind: 'simple'|'pointer'|'array'|'compound'|'unknown'
        """
        if type_die is None:
            return "unknown", 0, None, "unknown"

        # Снять модификаторы/typedef
        type_die = self.unwrap_qualifiers(dwarf_info, type_die, cu_offset)

        tag = type_die.tag

        if tag == 'DW_TAG_base_type':
            name, size = self.decode_base_type(type_die)
            return name, size, type_die, "simple"

        if tag == 'DW_TAG_enumeration_type':
            size_attr = type_die.attributes.get('DW_AT_byte_size')
            size = size_attr.value if size_attr else 0
            # Имя enum часто как typedef; показываем как uintX по размеру
            name = {1: "int8_t", 2: "int16_t", 4: "int32_t", 8: "int64_t"}.get(size, "int32_t")
            return name, size, type_die, "simple"

        if tag == 'DW_TAG_pointer_type':
            # Указатель может не иметь byte_size — берем из elfclass
            return "pointer", (self.pointer_size or 0), type_die, "pointer"

        if tag == 'DW_TAG_array_type':
            # Для массива сохраним как "array of <elem>"
            at_type = type_die.attributes.get('DW_AT_type')
            if at_type:
                elem_die = dwarf_info.get_DIE_from_refaddr(at_type.value + cu_offset)
                elem_name, elem_size, _, kind = self.resolve_type(dwarf_info, elem_die, cu_offset)
                name = f"array of {elem_name}"
                # Вычисляем размер массива
                array_size = self.get_array_size(type_die, dwarf_info, cu_offset)
                return name, array_size, type_die, "array"
            return "array", 0, type_die, "array"

        if tag in ('DW_TAG_structure_type', 'DW_TAG_class_type'):
            # Для структур/классов получаем общий размер
            size_attr = type_die.attributes.get('DW_AT_byte_size')
            size = size_attr.value if size_attr else 0
            return "compound", size, type_die, "compound"

        # Fallback — попробуем DW_AT_byte_size
        size_attr = type_die.attributes.get('DW_AT_byte_size')
        size = size_attr.value if size_attr else 0
        return "unknown_type", size, type_die, "unknown"

    # ---------- Члены compound-типа (struct/class) с рекурсией ----------

    def collect_compound_members(self, dwarf_info, compound_die, cu_offset, base_address, prefix):
        """
        Рекурсивно проходит все поля struct/class.
        Сохраняет только конечные (простые) поля в self.var_library c полным именем.
        """
        for child in compound_die.iter_children():
            if child.tag != 'DW_TAG_member' or 'DW_AT_name' not in child.attributes:
                continue

            name = child.attributes['DW_AT_name'].value.decode()
            full_name = f"{prefix}.{name}"

            # Смещение поля
            offset_attr = child.attributes.get('DW_AT_data_member_location')
            offset = offset_attr.value if offset_attr else 0
            address = base_address + offset

            # Тип поля
            if 'DW_AT_type' not in child.attributes:
                # без типа — пропускаем
                continue
            ref = child.attributes['DW_AT_type'].value + cu_offset
            field_die = dwarf_info.get_DIE_from_refaddr(ref)

            type_name, type_size, final_die, kind = self.resolve_type(dwarf_info, field_die, cu_offset)

            if kind == "compound":
                # Вложенная структура/класс: рекурсивно спускаемся
                self.collect_compound_members(dwarf_info, final_die, cu_offset, address, full_name)
            else:
                # Конечный (простой/указатель/массив/enum/базовый)
                size = type_size
                # Если размер не найден (0), но это указатель — подставим pointer_size
                if type_name not in self.forbidden_types and address not in self.seen_addresses:

                    self.seen_addresses.add(address)

                    if size is None:
                        size = 0

                    self.var_library[full_name] = {
                        'address': address,
                        'type': type_name,
                        'size': size
                    }

    # ---------- Определение типа переменной ----------

    def get_variable_type(self, dwarf_info, variable_name, symbol_address, symbol_size):
        """
        Определяет тип переменной и собирает информацию о ней.
        symbol_size используется для переменных без DWARF информации о размере.
        """
        for CU in dwarf_info.iter_CUs():
            for die in CU.iter_DIEs():
                if die.tag != 'DW_TAG_variable':
                    continue
                name_attr = die.attributes.get('DW_AT_name')
                if not name_attr:
                    continue
                if name_attr.value.decode() != variable_name:
                    continue

                # Тип переменной
                at_type = die.attributes.get('DW_AT_type')
                if not at_type:
                    return "unknown", symbol_size

                type_die = dwarf_info.get_DIE_from_refaddr(at_type.value + CU.cu_offset)

                # Разрешаем тип и решаем, compound ли он
                type_name, type_size, final_die, kind = self.resolve_type(dwarf_info, type_die, CU.cu_offset)

                if kind == "compound":
                    # Собираем рекурсивно все конечные поля
                    self.collect_compound_members(dwarf_info, final_die, CU.cu_offset, symbol_address, variable_name)
                    return {'members': 'compound'}, type_size
                else:
                    # Если размер из DWARF равен 0, используем symbol_size
                    if type_size == 0 and symbol_size > 0:
                        type_size = symbol_size
                    return type_name, type_size

        return "unknown", symbol_size

    # ---------- Сбор переменных из .bss ----------

    def collect_bss_vars(self, elf_file):
        """
        Сбор переменных из секции .bss с отслеживанием прогресса

        Args:
            elf_file: путь к ELF файлу для анализа

        Returns:
            dict: словарь с найденными переменными

        Raises:
            FileNotFoundError: если файл не существует
            ElfParsingError: если возникла ошибка парсинга
        """
        try:
            # Сброс состояния перед новым парсингом
            self.elf_file = elf_file
            self.var_library = {}
            self.seen_addresses = set()
            self.pointer_size = 0

            self._update_progress(0)

            # Проверка существования файла
            if not os.path.exists(elf_file):
                raise FileNotFoundError(f"ELF файл не найден: {elf_file}")

            with open(elf_file, 'rb') as f:
                elffile = ELFFile(f)
                self._update_progress(5)

                # Размер указателя по ELF (32/64)
                self.pointer_size = elffile.elfclass // 8

                if not elffile.has_dwarf_info():
                    raise ElfParsingError("Файл не содержит DWARF-информации!")

                dwarf_info = elffile.get_dwarf_info()
                self._update_progress(10)

                sym_tab = elffile.get_section_by_name('.symtab')
                if not sym_tab:
                    raise ElfParsingError("Таблица символов .symtab не найдена!")

                # Получаем общее количество символов для прогресса
                symbols = list(sym_tab.iter_symbols())
                total_symbols = len(symbols)

                if total_symbols == 0:
                    self._update_progress(100)
                    return self.var_library

                processed_symbols = 0

                for symbol in symbols:
                    processed_symbols += 1

                    # Обновляем прогресс
                    if processed_symbols % 10 == 0 or processed_symbols == total_symbols:
                        progress = 10 + (processed_symbols / total_symbols * 80)
                        self._update_progress(min(90, int(progress)))

                    if (
                            symbol.entry['st_shndx'] == 'SHN_UNDEF' or
                            not symbol.name or
                            symbol.entry['st_size'] == 0
                    ):
                        continue

                    section = elffile.get_section(symbol.entry['st_shndx'])
                    if section.name != '.bss':
                        continue

                    symbol_address = symbol.entry.get('st_value')
                    if symbol_address is None:
                        continue

                    symbol_size = symbol.entry['st_size']

                    var_type, var_size = self.get_variable_type(dwarf_info, symbol.name, symbol_address, symbol_size)

                    # Если это compound — его поля уже положены в var_library внутри get_variable_type
                    if isinstance(var_type, dict):
                        # # Для структур/классов можем также сохранить общую информацию
                        # if symbol_address not in self.seen_addresses:
                        #     self.seen_addresses.add(symbol_address)
                        #     self.var_library[symbol.name] = {
                        #         'address': symbol_address,
                        #         'type': 'struct/class',
                        #         'size': var_size
                        #     }
                        continue

                    if var_type in self.forbidden_types or symbol_address in self.seen_addresses:
                        continue

                    # Иначе — простая переменная, положим напрямую
                    if var_size == 0 and symbol_size > 0:
                        var_size = symbol_size

                    self.seen_addresses.add(symbol_address)

                    self.var_library[symbol.name] = {
                        'address': symbol_address,
                        'type': var_type,
                        'size': var_size
                    }

                self._update_progress(100)
                return self.var_library

        except FileNotFoundError:
            raise
        except ElfParsingError:
            raise
        except Exception as e:
            raise ElfParsingError(f"Ошибка при парсинге ELF файла: {str(e)}")

    # ---------- Вывод ----------

    def print_table(self):
        """Вывод таблицы переменных в консоль"""
        if not self.var_library:
            print("Нет данных о переменных в .bss!")
            return

        # Сортируем по адресу
        sorted_vars = sorted(self.var_library.items(), key=lambda kv: kv[1]['address'])

        for name, info in sorted_vars:
            print(f"var: {name} {info}, hex_adr: {hex(info['address'])}")

    def get_variables(self):
        """Получение словаря переменных"""
        return self.var_library

    def clear(self):
        """Очистка состояния инспектора"""
        self.elf_file = None
        self.var_library = {}
        self.pointer_size = 0
        self.seen_addresses = set()


if __name__ == "__main__":
    # Пример использования с обработкой ошибок
    try:
        inspector = BssInspector()


        # Демонстрация прогресса
        def progress_callback(value):
            print(f"Прогресс: {value}%")


        inspector.progress_callback = progress_callback

        # Парсинг файла
        variables = inspector.collect_bss_vars("test_data.elf")

        # Вывод результатов
        inspector.print_table()

    except FileNotFoundError as e:
        print(f"Ошибка: {e}")
    except ElfParsingError as e:
        print(f"Ошибка парсинга: {e}")
    except Exception as e:
        print(f"Неожиданная ошибка: {e}")