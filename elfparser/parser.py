#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ELF Parser - BSS Section Inspector for STM32
============================================

Анализ секции .bss ELF-файлов с DWARF debug информацией.
Извлекает переменные, их адреса, типы и размеры.
Деманглинг C++ имён через локальный arm-none-eabi-c++filt.exe.

Особенности:
- Полный разбор compound-типов (struct/class) и union (DW_TAG_union_type)
- Нормализация имён типов для сопоставления под разными namespace (CAN::CanSWHandler vs Global::CAN1_SWHandler)
- Поиск «полного определения» типа (не декларации) и разворачивание членов
- Fallback по имени типа и принудительное разворачивание корневых compound/union
- Устойчивая обработка DWARF-артефактов: безопасные ссылки, try/except, диагностика
- 1-байтовые неизвестные переменные считаются флагами (uint8_t)

Author: Uneld
Date: 11.12.2025
Version: 2.5
License: MIT
"""

from elftools.elf.elffile import ELFFile
from elftools.dwarf.dwarf_expr import DWARFExprParser
import os
import sys
import subprocess
from pathlib import Path
from enum import IntEnum

class ElfParsingError(Exception):
    pass


class AlignPattern(IntEnum):
    ZERO = 0x00  # Заполнение нулями
    INVERTED = 0xFF  # Заполнение единицами (0xFF)


class BssInspector:
    def __init__(self, elf_progress_callback=None):
        self.elf_file = None
        self.var_library = {}
        self.pointer_size = 0
        self.seen_addresses = set()  # (name, address) — разрешаем перекрытия union
        self.permission_types = {
            # целые
            "int8_t": True,
            "int16_t": True,
            "int32_t": True,
            # "int64_t": True,
            "uint8_t": True,
            "uint16_t": True,
            "uint32_t": True,
            # "uint64_t": True,

            # char / bool
            "char": True,
            "signed char": True,
            "unsigned char": True,
            "bool": True,

            # вещественные
            "float": True,
            # "double": True,
            # "long double": True,

            # указатели на примитивы
            # "pointer to int8_t": True,
            # "pointer to int16_t": True,
            # "pointer to int32_t": True,
            # "pointer to int64_t": True,
            # "pointer to uint8_t": True,
            # "pointer to uint16_t": True,
            # "pointer to uint32_t": True,
            # "pointer to uint64_t": True,
            # "pointer to float": True,
            # "pointer to double": True,

            # массивы примитивов
            "array of int8_t": True,
            "array of int16_t": True,
            "array of int32_t": True,
            # "array of int64_t": True,
            "array of uint8_t": True,
            "array of uint16_t": True,
            "array of uint32_t": True,
            # "array of uint64_t": True,
            "array of float": True,
            # "array of double": True,
        }
        self.progress_callback = elf_progress_callback

        self._demangler_path = self._resolve_local_demangler()
        self._demangle_warned = False
        self._demangle_cache = {}
        self.type_index = {}  # нормализованные ключи → список (die, cu_offset, size, full_name)

        self._expr_parser = None
        # --- Кеши для ускорения ---
        self._type_cache = {}      # die.offset -> (type_name, size, final_die, kind)
        self._var_index = {}       # raw_name -> [(die, cu_offset), ...]
        self._array_info_cache = {} # array_die.offset -> (elem_die, elem_type_name, elem_size, elem_kind, count, total_size)
        self._norm_cache = {}      # name -> (norm_full, norm_short)
        self._size_cache = {}      # die.offset -> byte_size

    @staticmethod
    def _is_mangled(name: str) -> bool:
        return name.startswith("_Z")

    @staticmethod
    def _get_bin_path():
        """
        Определяет путь к папке с данными elfparser.
        Работает и в режиме разработки, и в собранном exe.
        """

        # 1. Если мы в собранном exe (PyInstaller)
        if getattr(sys, 'frozen', False):
            # 1.1 Сначала проверяем папку рядом с exe
            exe_dir = Path(sys.executable).parent
            data_in_exe_dir = exe_dir / "bin"
            if data_in_exe_dir.exists():
                return data_in_exe_dir

            # 1.2 Проверяем временную папку PyInstaller
            if hasattr(sys, '_MEIPASS'):
                meipass_data = Path(sys._MEIPASS) / "bin"
                if meipass_data.exists():
                    return meipass_data

        # 2. Режим разработки - ищем рядом с parser.py
        dev_path = Path(__file__).resolve().parent / "bin"
        if dev_path.exists():
            return dev_path

        base_dir = os.path.dirname(os.path.abspath(__file__))
        bin_dir = os.path.join(base_dir, "bin")
        return bin_dir

    @staticmethod
    def _resolve_local_demangler() -> str:
        bin_dir = BssInspector._get_bin_path()
        # print(bin_dir)
        return os.path.join(bin_dir, "arm-none-eabi-c++filt.exe")

    @staticmethod
    def _is_forward_declaration(die):
        try:
            decl = die.attributes.get('DW_AT_declaration')
            return bool(decl and decl.value)
        except Exception:
            return False

    # ---------- Безопасные обращения к DIE ----------
    @staticmethod
    def _safe_get_die(dwarf_info, refaddr, cu_offset):
        """Безопасно получить DIE по ссылке. Возвращает None при любой ошибке."""
        try:
            return dwarf_info.get_DIE_from_refaddr(refaddr + cu_offset)
        except Exception:
            return None

    # ---------- Поиск полного определения типа ----------
    @staticmethod
    def _die_has_members(die):
        try:
            if die is None:
                return False
            for child in die.iter_children():
                if child.tag == 'DW_TAG_member':
                    return True
            return False
        except Exception:
            return False

    # ---------- Сопоставление имён переменных ----------
    @staticmethod
    def _names_match(dwarf_name: str, demangled_var_name: str) -> bool:
        return dwarf_name == demangled_var_name or demangled_var_name.endswith(dwarf_name)

    def _update_progress(self, value):
        if self.progress_callback and callable(self.progress_callback):
            self.progress_callback(value)

    def demangle(self, name: str) -> str:
        if not name:
            return name
        cached = self._demangle_cache.get(name)
        if cached is not None:
            return cached

        if not os.path.exists(self._demangler_path):
            if not self._demangle_warned:
                print(f"[WARN] arm-none-eabi-c++filt.exe не найден; возвращаю исходные имена. {self._demangler_path}",
                      file=sys.stderr)
                self._demangle_warned = True
            self._demangle_cache[name] = name
            return name

        try:
            proc = subprocess.run(
                [self._demangler_path, name],
                capture_output=True,
                text=True,
                timeout=2.0,
                check=False,
                creationflags=subprocess.CREATE_NO_WINDOW  # 👉 убираем моргание окон
            )
            out = (proc.stdout or "").strip()
            result = out if (proc.returncode == 0 and out) else name
            self._demangle_cache[name] = result
            return result
        except subprocess.TimeoutExpired:
            self._demangle_cache[name] = name
            return name
        except Exception:
            self._demangle_cache[name] = name
            return name

            # ---------- Нормализация имён ----------

    def _norm_short(self, name: str) -> str:
        """Короткий нормализованный ключ типа: демангл, хвост без namespace, lower."""
        if not name:
            return ""
        full = self.demangle(name)
        short = full.split("::")[-1].strip().lower()
        return short

    def _norm_full(self, name: str) -> str:
        """Полный нормализованный ключ типа: демангл, lower."""
        if not name:
            return ""
        return self.demangle(name).strip().lower()
    def _norm_cached(self, name: str):
        """Кешированная нормализация: возвращает (norm_full, norm_short)."""
        if not name:
            return ("", "")
        cached = self._norm_cache.get(name)
        if cached is not None:
            return cached
        nf = self._norm_full(name)
        ns = self._norm_short(name)
        self._norm_cache[name] = (nf, ns)
        return nf, ns

    def _build_var_index(self, dwarf_info):
        """Индексируем DW_TAG_variable по сырым именам для O(1) поиска."""
        self._var_index = {}
        for CU in dwarf_info.iter_CUs():
            cu_offset = CU.cu_offset
            for die in CU.iter_DIEs():
                if die.tag != 'DW_TAG_variable':
                    continue
                name_attr = die.attributes.get('DW_AT_name')
                if not name_attr:
                    continue
                try:
                    raw_name = name_attr.value.decode()
                except Exception:
                    continue
                self._var_index.setdefault(raw_name, []).append((die, cu_offset))

    def _cached_resolve_type(self, dwarf_info, type_die, cu_offset):
        """Кешируемый resolve_type — ключ по глобальному offset DIE."""
        key = type_die.offset
        if key in self._type_cache:
            return self._type_cache[key]
        result = self.resolve_type(dwarf_info, type_die, cu_offset)
        self._type_cache[key] = result
        return result

    def _get_array_info(self, dwarf_info, array_die, cu_offset):
        """Кешированная информация о массиве: элемент, количество, размер."""
        key = array_die.offset
        if key in self._array_info_cache:
            return self._array_info_cache[key]

        at_type = array_die.attributes.get('DW_AT_type')
        if not at_type:
            self._array_info_cache[key] = None
            return None
        elem_die = self._safe_get_die(dwarf_info, at_type.value, cu_offset)
        if not elem_die:
            self._array_info_cache[key] = None
            return None

        elem_type_name, elem_size, elem_final_die, elem_kind = self._cached_resolve_type(
            dwarf_info, elem_die, cu_offset
        )

        count = 1
        for child in array_die.iter_children():
            if child.tag == 'DW_TAG_subrange_type':
                count_attr = child.attributes.get('DW_AT_count')
                upper = child.attributes.get('DW_AT_upper_bound')
                if count_attr:
                    count *= count_attr.value
                elif upper:
                    lower = child.attributes.get('DW_AT_lower_bound')
                    lb = lower.value if lower else 0
                    count *= (upper.value - lb + 1)

        total_size = count * elem_size if elem_size > 0 else 0
        self._array_info_cache[key] = (elem_die, elem_type_name, elem_size, elem_kind, count, total_size)
        return self._array_info_cache[key]

    def _die_byte_size(self, die):
        """Быстрое получение DW_AT_byte_size с кешем."""
        key = die.offset
        if key in self._size_cache:
            return self._size_cache[key]
        size_attr = die.attributes.get('DW_AT_byte_size')
        val = size_attr.value if size_attr else 0
        self._size_cache[key] = val
        return val


    # ---------- Типы ----------

    def decode_base_type(self, type_die):
        enc_attr = type_die.attributes.get('DW_AT_encoding')
        size_attr = type_die.attributes.get('DW_AT_byte_size')
        if not enc_attr or not size_attr:
            return "unknown", 0
        encoding = enc_attr.value
        size = size_attr.value
        if encoding == 0x01:
            return "pointer", self.pointer_size or size
        elif encoding == 0x02:
            return "uint8_t", size
        elif encoding == 0x03:
            return "complex", size
        elif encoding == 0x04:
            return {4: "float", 8: "double", 16: "long double"}.get(size, "float"), size
        elif encoding == 0x05:
            return {1: "int8_t", 2: "int16_t", 4: "int32_t", 8: "int64_t"}.get(size, "int"), size
        elif encoding == 0x06:
            return "int8_t", size
        elif encoding == 0x07:
            return {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}.get(size, "uint"), size
        elif encoding == 0x08:
            return "uint8_t", size
        return "unknown", size

    def unwrap_qualifiers(self, dwarf_info, type_die, cu_offset):
        try:
            while type_die and type_die.tag in (
                    'DW_TAG_volatile_type', 'DW_TAG_const_type', 'DW_TAG_restrict_type', 'DW_TAG_typedef'
            ):
                at_type = type_die.attributes.get('DW_AT_type')
                if not at_type:
                    break
                type_die = self._safe_get_die(dwarf_info, at_type.value, cu_offset)
                if type_die is None:
                    break
            return type_die
        except Exception:
            return type_die

    def _exprloc_offset(self, attr):
        """Пытаемся вытащить константный смещение из DW_FORM_exprloc (DW_AT_data_member_location)."""
        try:
            if hasattr(attr, 'form') and attr.form == 'DW_FORM_exprloc':
                ops = self._expr_parser.parse_expr(attr.value)
                for op in ops:
                    if op.op_name == 'DW_OP_plus_uconst' and len(op.args) == 1:
                        return int(op.args[0])
        except Exception:
            pass
        return 0

    def get_array_size(self, array_die, dwarf_info, cu_offset):
        try:
            total_elements = 1
            element_size = 0
            at_type = array_die.attributes.get('DW_AT_type')
            if at_type:
                elem_die = self._safe_get_die(dwarf_info, at_type.value, cu_offset)
                if elem_die:
                    _, elem_size, _, _ = self.resolve_type(dwarf_info, elem_die, cu_offset)
                    element_size = elem_size
            for child in array_die.iter_children():
                if child.tag == 'DW_TAG_subrange_type':
                    count_attr = child.attributes.get('DW_AT_count')
                    upper_bound_attr = child.attributes.get('DW_AT_upper_bound')
                    if count_attr:
                        total_elements *= count_attr.value
                    elif upper_bound_attr:
                        lower_bound_attr = child.attributes.get('DW_AT_lower_bound')
                        lower_bound = lower_bound_attr.value if lower_bound_attr else 0
                        total_elements *= (upper_bound_attr.value - lower_bound + 1)
            return total_elements * element_size if element_size > 0 else 0
        except Exception:
            return 0

    def resolve_type(self, dwarf_info, type_die, cu_offset):
        """Возвращает (type_name, size, final_die, kind). kind: simple|compound|array|pointer|union|unknown"""
        try:
            if type_die is None:
                return "unknown", 0, None, "unknown"

            type_die = self.unwrap_qualifiers(dwarf_info, type_die, cu_offset)
            if type_die is None:
                return "unknown", 0, None, "unknown"

            tag = getattr(type_die, 'tag', None)
            if tag is None:
                return "unknown", 0, None, "unknown"

            if tag == 'DW_TAG_base_type':
                name, size = self.decode_base_type(type_die)
                return self.demangle(name), size, type_die, "simple"

            if tag == 'DW_TAG_enumeration_type':
                size_attr = type_die.attributes.get('DW_AT_byte_size')
                size = size_attr.value if size_attr else 0
                name = {1: "int8_t", 2: "int16_t", 4: "int32_t", 8: "int64_t"}.get(size, "int32_t")
                return self.demangle(name), size, type_die, "simple"

            if tag == 'DW_TAG_pointer_type':
                at_type = type_die.attributes.get('DW_AT_type')
                if at_type:
                    pointee_die = self._safe_get_die(dwarf_info, at_type.value, cu_offset)
                    if pointee_die:
                        pointee_name, _, _, _ = self.resolve_type(dwarf_info, pointee_die, cu_offset)
                        return self.demangle(f"pointer to {pointee_name}"), (
                                    self.pointer_size or 0), type_die, "pointer"
                return self.demangle("pointer"), (self.pointer_size or 0), type_die, "pointer"

            if tag == 'DW_TAG_array_type':
                at_type = type_die.attributes.get('DW_AT_type')
                if at_type:
                    elem_die = self._safe_get_die(dwarf_info, at_type.value, cu_offset)
                    if elem_die:
                        elem_name, elem_size, _, _ = self.resolve_type(dwarf_info, elem_die, cu_offset)
                        name = f"array of {elem_name}"
                        array_size = self.get_array_size(type_die, dwarf_info, cu_offset)
                        # Сохраняем информацию о размере элемента и количестве элементов
                        return self.demangle(name), array_size, type_die, "array"
                return self.demangle("array"), 0, type_die, "array"

            if tag in ('DW_TAG_structure_type', 'DW_TAG_class_type'):
                size_attr = type_die.attributes.get('DW_AT_byte_size')
                size = size_attr.value if size_attr else 0
                type_name_attr = type_die.attributes.get('DW_AT_name')
                type_name = type_name_attr.value.decode() if type_name_attr else "compound"
                return self.demangle(type_name), size, type_die, "compound"

            if tag == 'DW_TAG_union_type':
                size_attr = type_die.attributes.get('DW_AT_byte_size')
                size = size_attr.value if size_attr else 0
                type_name_attr = type_die.attributes.get('DW_AT_name')
                type_name = type_name_attr.value.decode() if type_name_attr else "union"
                return self.demangle(type_name), size, type_die, "union"

            size_attr = type_die.attributes.get('DW_AT_byte_size')
            size = size_attr.value if size_attr else 0
            return self.demangle("unknown_type"), size, type_die, "unknown"
        except Exception:
            return "unknown", 0, None, "unknown"

    # ---------- Индексация типов ----------

    def _build_type_index(self, dwarf_info):
        """Индексируем все struct/class/union по полному и короткому нормализованным ключам."""
        self.type_index = {}

        def add_entry(key, add_die, cu_off, add_size, add_full_name):
            self.type_index.setdefault(key, []).append((add_die, cu_off, add_size, add_full_name))

        for CU in dwarf_info.iter_CUs():
            cu_offset = CU.cu_offset
            for die in CU.iter_DIEs():
                if die.tag in ('DW_TAG_structure_type', 'DW_TAG_class_type', 'DW_TAG_union_type'):
                    name_attr = die.attributes.get('DW_AT_name')
                    if not name_attr:
                        continue
                    try:
                        raw_name = name_attr.value.decode()
                    except Exception:
                        continue
                    full_name = self.demangle(raw_name)
                    size_attr = die.attributes.get('DW_AT_byte_size')
                    size = size_attr.value if size_attr else 0
                    key_full = self._norm_full(full_name)
                    key_short = self._norm_short(full_name)
                    add_entry(key_full, die, cu_offset, size, full_name)
                    add_entry(key_short, die, cu_offset, size, full_name)

    def _find_complete_type_die(self, dwarf_info, name_full_or_short):
        """Ищет полное определение типа (die с членами, не декларацию), учитывая namespace."""
        try:
            key_full, key_short = self._norm_cached(name_full_or_short)

            candidates = []
            for key in (key_full, key_short):
                candidates.extend(self.type_index.get(key, []))

            if not candidates:
                target_names = {key_full, key_short}
                for CU in dwarf_info.iter_CUs():
                    cu_off = CU.cu_offset
                    for die in CU.iter_DIEs():
                        if die.tag in ('DW_TAG_structure_type', 'DW_TAG_class_type', 'DW_TAG_union_type'):
                            name_attr = die.attributes.get('DW_AT_name')
                            if not name_attr:
                                continue
                            try:
                                dn = self.demangle(name_attr.value.decode())
                            except Exception:
                                continue
                            dn_full, dn_short = self._norm_cached(dn)
                            if (dn_full in target_names) or (dn_short in target_names):
                                size = self._die_byte_size(die)
                                candidates.append((die, cu_off, size, dn))

            if not candidates:
                return None

            def score(entry):
                score_die, score_cu_off, score_size, full_name = entry
                has_members = self._die_has_members(score_die)
                is_decl = self._is_forward_declaration(score_die)
                return (
                    0 if is_decl else 1,
                    1 if has_members else 0,
                    1 if score_size else 0
                )

            best = max(candidates, key=score)
            return best
        except Exception:
            return None

    # ---------- Разворачивание ----------

    def collect_compound_members(self, dwarf_info, compound_die, cu_offset, base_address, prefix):
        try:
            for child in compound_die.iter_children():
                if child.tag != 'DW_TAG_member' or 'DW_AT_name' not in child.attributes:
                    continue
                name = child.attributes['DW_AT_name'].value.decode()
                full_name = f"{prefix}.{name}"

                offset = 0
                offset_attr = child.attributes.get('DW_AT_data_member_location')
                if offset_attr:
                    try:
                        off_expr = self._exprloc_offset(offset_attr)
                        if off_expr:
                            offset = off_expr
                        else:
                            offset = int(offset_attr.value)
                    except Exception:
                        offset = 0
                address = base_address + offset

                if 'DW_AT_type' not in child.attributes:
                    continue
                field_die = self._safe_get_die(dwarf_info, child.attributes['DW_AT_type'].value, cu_offset)
                if field_die is None:
                    continue

                try:
                    type_name, type_size, final_die, kind = self._cached_resolve_type(dwarf_info, field_die, cu_offset)
                except Exception:
                    continue

                # ===== МАССИВЫ =====
                if kind == "array" and final_die:
                    arr_info = self._get_array_info(dwarf_info, final_die, cu_offset)
                    if arr_info:
                        elem_die, elem_type_name, elem_size, elem_kind, count, _ = arr_info
                        if elem_kind in ("compound", "union") and count > 0:
                            complete = self._find_complete_type_die(dwarf_info, elem_type_name)
                            if complete:
                                die_c, cu_off_c, _, _ = complete
                            else:
                                die_c, cu_off_c = elem_die, cu_offset
                            for i in range(count):
                                element_address = address + (i * elem_size)
                                element_prefix = f"{full_name}[{i}]"
                                if elem_kind == "compound":
                                    self.collect_compound_members(dwarf_info, die_c, cu_off_c, element_address, element_prefix)
                                else:
                                    self.collect_union_members(dwarf_info, die_c, cu_off_c, element_address, element_prefix)
                            continue
                        elif f"array of {elem_type_name}" in self.permission_types:
                            key = (full_name, address)
                            if key not in self.seen_addresses:
                                self.seen_addresses.add(key)
                                self.var_library[full_name] = {
                                    'address': address,
                                    'type': f"array of {elem_type_name}",
                                    'size': count * elem_size if elem_size > 0 else type_size
                                }
                            continue

                if kind in ("compound", "union"):
                    complete = self._find_complete_type_die(dwarf_info, type_name)
                    if complete:
                        die_c, cu_off_c, _, type_name = complete
                        if kind == "compound":
                            self.collect_compound_members(dwarf_info, die_c, cu_off_c, address, full_name)
                        else:
                            self.collect_union_members(dwarf_info, die_c, cu_off_c, address, full_name)
                    else:
                        if kind == "compound":
                            self.collect_compound_members(dwarf_info, final_die, cu_offset, address, full_name)
                        else:
                            self.collect_union_members(dwarf_info, final_die, cu_offset, address, full_name)
                else:
                    key = (full_name, address)
                    if type_name in self.permission_types and key not in self.seen_addresses:
                        self.seen_addresses.add(key)
                        self.var_library[full_name] = {
                            'address': address,
                            'type': self.demangle(type_name),
                            'size': type_size
                        }
        except Exception:
            pass

    def collect_union_members(self, dwarf_info, union_die, cu_offset, base_address, prefix):
        try:
            for child in union_die.iter_children():
                if child.tag != 'DW_TAG_member' or 'DW_AT_name' not in child.attributes:
                    continue
                name = child.attributes['DW_AT_name'].value.decode()
                full_name = f"{prefix}.{name}"
                address = base_address

                if 'DW_AT_type' not in child.attributes:
                    continue
                field_die = self._safe_get_die(dwarf_info, child.attributes['DW_AT_type'].value, cu_offset)
                if field_die is None:
                    continue

                try:
                    type_name, type_size, final_die, kind = self._cached_resolve_type(dwarf_info, field_die, cu_offset)
                except Exception:
                    continue

                # ===== МАССИВЫ В UNION =====
                if kind == "array" and final_die:
                    arr_info = self._get_array_info(dwarf_info, final_die, cu_offset)
                    if arr_info:
                        elem_die, elem_type_name, elem_size, elem_kind, count, _ = arr_info
                        if elem_kind in ("compound", "union") and count > 0:
                            complete = self._find_complete_type_die(dwarf_info, elem_type_name)
                            if complete:
                                die_c, cu_off_c, _, _ = complete
                            else:
                                die_c, cu_off_c = elem_die, cu_offset
                            for i in range(count):
                                element_address = address + (i * elem_size)
                                element_prefix = f"{full_name}[{i}]"
                                if elem_kind == "compound":
                                    self.collect_compound_members(dwarf_info, die_c, cu_off_c, element_address, element_prefix)
                                else:
                                    self.collect_union_members(dwarf_info, die_c, cu_off_c, element_address, element_prefix)
                            continue
                        elif f"array of {elem_type_name}" in self.permission_types:
                            key = (full_name, address)
                            if key not in self.seen_addresses:
                                self.seen_addresses.add(key)
                                self.var_library[full_name] = {
                                    'address': address,
                                    'type': f"array of {elem_type_name}",
                                    'size': count * elem_size if elem_size > 0 else type_size
                                }
                            continue

                if kind in ("compound", "union"):
                    complete = self._find_complete_type_die(dwarf_info, type_name)
                    if complete:
                        die_c, cu_off_c, _, type_name = complete
                        if kind == "compound":
                            self.collect_compound_members(dwarf_info, die_c, cu_off_c, address, full_name)
                        else:
                            self.collect_union_members(dwarf_info, die_c, cu_off_c, address, full_name)
                    else:
                        if kind == "compound":
                            self.collect_compound_members(dwarf_info, final_die, cu_offset, address, full_name)
                        else:
                            self.collect_union_members(dwarf_info, final_die, cu_offset, address, full_name)
                else:
                    key = (full_name, address)
                    if type_name in self.permission_types and key not in self.seen_addresses:
                        self.seen_addresses.add(key)
                        self.var_library[full_name] = {
                            'address': address,
                            'type': self.demangle(type_name),
                            'size': type_size
                        }
        except Exception:
            pass

    def _expand_root_compound_union(self, dwarf_info, var_type_name, demangled_name, symbol_address):
        try:
            # Если это массив - обрабатываем его элементы
            if var_type_name.startswith("array of "):
                # Извлекаем имя типа элемента
                elem_type_name = var_type_name[9:]  # убираем "array of "
                complete = self._find_complete_type_die(dwarf_info, elem_type_name)
                if not complete:
                    complete = self._find_complete_type_die(dwarf_info, elem_type_name.split("::")[-1])

                if complete:
                    die_t, cu_off, _, full_name = complete
                    # Здесь нужно получить размер массива и развернуть каждый элемент
                    # Для этого нужно найти DIE массива в DWARF
                    # ... (логика получения размера массива и разворачивания)
                return var_type_name

            # Существующая логика для обычных структур/объединений
            complete = self._find_complete_type_die(dwarf_info, var_type_name)
            if not complete:
                complete = self._find_complete_type_die(dwarf_info, demangled_name)
            if not complete:
                complete = self._find_complete_type_die(dwarf_info, demangled_name.split("::")[-1])

            if complete:
                die_t, cu_off, _, full_name = complete
                tname, _, _, tkind = self.resolve_type(dwarf_info, die_t, cu_off)
                if tkind == "compound":
                    self.collect_compound_members(dwarf_info, die_t, cu_off, symbol_address, demangled_name)
                elif tkind == "union":
                    self.collect_union_members(dwarf_info, die_t, cu_off, symbol_address, demangled_name)
                return tname
            return None
        except Exception:
            return None

    # ---------- Основная типизация ----------

    def get_variable_type(self, dwarf_info, variable_name, symbol_address, symbol_size):
        demangled_var_name = self.demangle(variable_name)

        try:
            # Быстрый поиск через индекс (O(1) вместо полного обхода)
            candidates = self._var_index.get(variable_name, [])
            for die, cu_offset in candidates:
                try:
                    dwarf_name = die.attributes['DW_AT_name'].value.decode()
                except Exception:
                    continue
                if not self._names_match(dwarf_name, demangled_var_name):
                    continue

                at_type = die.attributes.get('DW_AT_type')
                if at_type:
                    type_die = self._safe_get_die(dwarf_info, at_type.value, cu_offset)
                    if not type_die:
                        continue
                    type_name, type_size, final_die, kind = self._cached_resolve_type(dwarf_info, type_die, cu_offset)

                    # Обработка массива структур/union на корневом уровне
                    if kind == "array" and final_die:
                        arr_info = self._get_array_info(dwarf_info, final_die, cu_offset)
                        if arr_info:
                            elem_die, elem_type_name, elem_size, elem_kind, count, array_size = arr_info
                            if elem_kind in ("compound", "union") and count > 0:
                                complete = self._find_complete_type_die(dwarf_info, elem_type_name)
                                if complete:
                                    die_c, cu_off_c, _, _ = complete
                                else:
                                    die_c, cu_off_c = elem_die, cu_offset
                                for i in range(count):
                                    addr = symbol_address + (i * elem_size)
                                    prefix = f"{demangled_var_name}[{i}]"
                                    if elem_kind == "compound":
                                        self.collect_compound_members(dwarf_info, die_c, cu_off_c, addr, prefix)
                                    else:
                                        self.collect_union_members(dwarf_info, die_c, cu_off_c, addr, prefix)
                                return type_name, array_size, kind

                    if kind in ("compound", "union"):
                        normalized_type_name = self._expand_root_compound_union(
                            dwarf_info, type_name, demangled_var_name, symbol_address
                        )
                        if normalized_type_name:
                            return normalized_type_name, (type_size or symbol_size), kind
                        if kind == "compound":
                            self.collect_compound_members(dwarf_info, final_die, cu_offset, symbol_address,
                                                          demangled_var_name)
                        else:
                            self.collect_union_members(dwarf_info, final_die, cu_offset, symbol_address,
                                                       demangled_var_name)
                        return type_name, (type_size or symbol_size), kind

                    return self.demangle(type_name), (type_size or symbol_size), kind
                break  # совпадение найдено, но нет типа — идём к fallback

            # Fallback для mangled
            if self._is_mangled(variable_name):
                normalized_type_name = self._expand_root_compound_union(
                    dwarf_info, demangled_var_name, demangled_var_name, symbol_address
                )
                if normalized_type_name:
                    complete = self._find_complete_type_die(dwarf_info, normalized_type_name)
                    size_best = complete[2] if complete else symbol_size
                    return normalized_type_name, (size_best or symbol_size), "compound"
                return demangled_var_name, symbol_size, "unknown"

            if symbol_size == 1:
                return "uint8_t", symbol_size, "simple"

            return "unknown", symbol_size, "unknown"

        except Exception as e_1:
            print(f"[DEBUG] get_variable_type failed for '{variable_name}' "
                  f"addr=0x{symbol_address:08x} size={symbol_size}: {e_1}", file=sys.stderr)
            return "unknown", symbol_size, "unknown"

    # ---------- Сбор из .bss ----------

    def collect_bss_vars(self, elf_file):
        """Сбор переменных из .bss с разворачиванием compound/union, даже при fallback."""
        try:
            self.elf_file = elf_file
            self.var_library = {}
            self.seen_addresses = set()
            self.pointer_size = 0
            self._type_cache = {}
            self._var_index = {}
            self._array_info_cache = {}
            self._norm_cache = {}
            self._size_cache = {}
            self._update_progress(0)

            if not os.path.exists(elf_file):
                raise FileNotFoundError(f"ELF файл не найден: {elf_file}")

            with open(elf_file, 'rb') as f:
                elffile = ELFFile(f)
                self._update_progress(5)
                self.pointer_size = elffile.elfclass // 8

                if not elffile.has_dwarf_info():
                    raise ElfParsingError("Файл не содержит DWARF-информации!")
                dwarf_info = elffile.get_dwarf_info()
                self._expr_parser = DWARFExprParser(dwarf_info.structs)
                self._update_progress(10)
                self._build_type_index(dwarf_info)
                self._build_var_index(dwarf_info)

                sym_tab = elffile.get_section_by_name('.symtab')
                if not sym_tab:
                    raise ElfParsingError("Таблица символов .symtab не найдена!")

                symbols = list(sym_tab.iter_symbols())
                total_symbols = len(symbols)
                if total_symbols == 0:
                    self._update_progress(100)
                    return self.var_library

                processed_symbols = 0
                for symbol in symbols:
                    processed_symbols += 1
                    if processed_symbols % 10 == 0 or processed_symbols == total_symbols:
                        progress = 10 + (processed_symbols / total_symbols * 80)
                        self._update_progress(min(90, int(progress)))

                    try:
                        if (symbol.entry['st_shndx'] == 'SHN_UNDEF' or
                                not symbol.name or
                                symbol.entry['st_size'] == 0):
                            continue

                        section = elffile.get_section(symbol.entry['st_shndx'])
                        if section.name not in ('.bss', '.data'):
                            continue

                        symbol_address = symbol.entry.get('st_value')
                        if symbol_address is None:
                            continue

                        symbol_size = symbol.entry['st_size']
                        demangled_name = self.demangle(symbol.name)

                        if demangled_name.startswith('__') or demangled_name.startswith(
                                '_ZTV') or demangled_name.startswith('_ZTI'):
                            continue

                        try:
                            var_type, var_size, kind = self.get_variable_type(
                                dwarf_info, symbol.name, symbol_address, symbol_size
                            )
                        except Exception as e_2:
                            print(f"[DEBUG] DWARF type resolution failed for symbol '{symbol.name}' "
                                  f"addr=0x{symbol_address:08x} size={symbol_size}: {e_2}", file=sys.stderr)
                            var_type, var_size, kind = ("unknown", symbol_size, "unknown")

                        # Разворачивание массивов структур уже выполнено в get_variable_type
                        # или collect_compound_members. Здесь только решаем, добавлять ли корень.
                        should_add = False
                        if var_type in self.permission_types:
                            should_add = True
                        elif kind in ("compound", "union"):
                            should_add = True
                        elif kind == "array" and var_type in self.permission_types:
                            should_add = True

                        if not should_add:
                            continue

                        if var_size == 0 and symbol_size > 0:
                            var_size = symbol_size

                        # Для compound/union корень уже развёрнут в get_variable_type;
                        # добавляем запись о корне только если её ещё нет
                        key = (demangled_name, symbol_address)
                        if key in self.seen_addresses:
                            continue
                        self.seen_addresses.add(key)

                        if kind in ("compound", "union"):
                            normalized_type_name = self._expand_root_compound_union(
                                dwarf_info, var_type, demangled_name, symbol_address
                            )
                            if normalized_type_name:
                                var_type = normalized_type_name

                        if kind == "unknown" and self._is_mangled(symbol.name):
                            var_type = demangled_name

                        self.var_library[demangled_name] = {
                            'address': symbol_address,
                            'type': var_type,
                            'size': var_size
                        }

                    except Exception as e_2:
                        print(f"[DEBUG] Symbol iteration failed for '{symbol.name}': {e_2}", file=sys.stderr)

                self._update_progress(100)
                return self.var_library

        except FileNotFoundError:
            raise
        except ElfParsingError:
            raise
        except Exception as e_2:
            raise ElfParsingError(f"Ошибка при парсинге ELF файла: {str(e_2)}")

    # ---------- Вывод ----------

    def print_table(self):
        if not self.var_library:
            print("Нет данных о переменных в .bss!")
            return
        sorted_vars = sorted(self.var_library.items(), key=lambda kv: kv[1]['address'])
        count = 0
        for name, info in sorted_vars:
            print(f"{name} {info}, hex_adr: {hex(info['address'])}")
            count += 1
        print(f"All variables: {count}")

    def get_variables(self):
        return self.var_library

    def clear(self):
        self.elf_file = None
        self.var_library = {}
        self.pointer_size = 0
        self.seen_addresses = set()
        self._type_cache = {}
        self._var_index = {}
        self._array_info_cache = {}
        self._norm_cache = {}
        self._size_cache = {}

    @staticmethod
    def build_flash_image_with_global_align(elf_file_path: str, align_pattern: AlignPattern = AlignPattern.ZERO):
        """
           Сборка образа FLASH с выравниванием блоков памяти

           Args:
               elf_file_path: путь к ELF файлу
               align_pattern: паттерн заполнения (AlignPattern.ZERO или AlignPattern.ONES)
           """
        # Проверка корректности паттерна
        if align_pattern not in (0x00, 0xFF):
            raise ValueError(f"align_pattern должен быть 0x00 или 0xFF, получено: {hex(align_pattern)}")

        with open(elf_file_path, "rb") as f:
            elf = ELFFile(f)
            flash_data = bytearray()
            sections_info = []
            offset = 0
            prev_addr = None
            prev_size = None

            fill_byte = align_pattern.value  # 0x00 или 0xFF

            for section in elf.iter_sections():
                name = section.name
                size = section['sh_size']
                if size == 0:
                    continue

                addr = section['sh_addr']
                if 0x08000000 <= addr < 0x080FFFFF or name == ".data":
                    data = section.data()
                    offset += size

                    if prev_addr is not None and name != ".data":
                        gap = addr - (prev_addr + prev_size)
                        if gap > 0:
                            # Используем указанный паттерн заполнения
                            flash_data.extend(bytes([fill_byte]) * gap)
                            # print(f"[PAD] Добавлено {gap} байт между {sections_info[-1][0]} и {name}")
                    flash_data.extend(data)

                    sections_info.append((name, addr, size, 0))
                    # print(f"[INFO] {name}, size={size}, addr={hex(addr)}, current_total={len(flash_data)}")

                    prev_addr = addr
                    prev_size = size

            # если указан путь для сохранения — пишем в файл
            # try:
            #     with open("C:\\flash_out.bin", "wb") as fout:
            #         fout.write(flash_data)
            # except e:
            #     print(f"err: {e}")
            # print(f"[SAVE] FLASH образ сохранён в {"flash_out.bin"}")

            return bytes(flash_data), sections_info


if __name__ == "__main__":
    try:
        inspector = BssInspector()


        def progress_callback(value):
            print(f"Прогресс: {value}%")


        inspector.progress_callback = progress_callback
        variables = inspector.collect_bss_vars("test_data.elf")
        inspector.print_table()

    except FileNotFoundError as e:
        print(f"Ошибка: {e}")
    except ElfParsingError as e:
        print(f"Ошибка парсинга: {e}")
    except Exception as e:
        print(f"Неожиданная ошибка: {e}")