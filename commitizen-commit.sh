#!/bin/bash

# Добавляем все изменения
git add . || { echo "❌ Ошибка при git add"; read -p "Нажмите Enter для выхода..."; exit 1; }

# Проверяем staged изменения
if git diff --cached --quiet; then
    echo "⚠️ Нет изменений для коммита"
    read -p "Нажмите Enter для выхода..."
    exit 1
fi

# Генерация сообщения через Commitizen
if cz commit --dry-run --write-message-to-file .cz_commit_msg.txt; then
    echo ""
    echo "🔎 Сгенерированное сообщение:"
    cat .cz_commit_msg.txt
    echo ""

    read -p "Хотите отредактировать сообщение перед коммитом? (y/n)(д/н): " edit_choice

	if [[ "$edit_choice" =~ ^[yYдД]$ ]]; then
        git commit -e -F .cz_commit_msg.txt
    else
        git commit -F .cz_commit_msg.txt
    fi

    rm .cz_commit_msg.txt
    echo ""
    echo "✅ Коммит создан!"
else
    echo "❌ Ошибка при генерации сообщения Commitizen"
fi

read -p "Нажмите Enter для выхода..."
