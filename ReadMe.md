## Описание

`BssInspector` - это Python-класс для анализа секции `.bss` в ELF-файлах с поддержкой DWARF-отладочной информации. Класс позволяет извлекать информацию о неинициализированных переменных, включая их адреса, типы данных и размеры.

## Основные возможности

- Анализ переменных в секции `.bss` ELF-файлов
- Поддержка различных типов данных (базовые типы, указатели, массивы, структуры)
- Рекурсивный анализ составных типов (struct/class)
- Автоматическое определение размера указателей на основе архитектуры (32/64 бита)
- Форматированный вывод результатов

## Требования

- Python 3.x
- `pyelftools` библиотека

## Установка зависимостей

```bash
pip install pyelftools
```

## Использование

```python
from ElfParser import BssInspector

# Создание инспектора для ELF-файла
inspector = BssInspector("your_file.elf")

# Сбор информации о переменных в .bss
inspector.collect_bss_vars()

# Вывод результатов
inspector.print_table()
```

## Пример вывода

```
var: global_var {'address': 536871436, 'type': 'uint32_t', 'size': 4}
var: struct_instance.member1 {'address': 536871440, 'type': 'int16_t', 'size': 2}
var: struct_instance.member2 {'address': 536871442, 'type': 'pointer', 'size': 4}
```