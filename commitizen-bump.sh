#!/bin/bash
# commitizen-bump.sh — ограниченный bump с лимитом 255 для major/minor/patch

LIMIT=255

# 1. Получаем текущую версию из .cz.yaml
VERSION=$(grep "version:" .cz.yaml | awk '{print $2}')
MAJOR=$(echo $VERSION | cut -d. -f1)
MINOR=$(echo $VERSION | cut -d. -f2)
PATCH=$(echo $VERSION | cut -d. -f3)

echo "🔎 Текущая версия: $VERSION"
echo "MAJOR=$MAJOR MINOR=$MINOR PATCH=$PATCH"

# 2. Проверяем лимиты
if [ "$MAJOR" -lt "$LIMIT" ] && [ "$MINOR" -lt "$LIMIT" ] && [ "$PATCH" -lt "$LIMIT" ]; then
    echo "✅ Все значения меньше $LIMIT — выполняем обычный cz bump..."
    if ! cz bump; then
        echo "⚠️ Ошибка выполнения cz bump"
    fi
else
    echo "⚠️ Достигнут лимит $LIMIT для одного из компонентов версии!"
    echo "Выберите действие:"
    echo "1) Задать новую версию вручную"
    echo "2) Увеличить MAJOR"
    echo "3) Увеличить MINOR"
    echo "4) Увеличить PATCH"

    read -p "Ваш выбор [1-4]: " choice

    case $choice in
        1)
            read -p "Введите новую версию (например 2.0.0): " new_version
            if ! cz bump --set-version "$new_version"; then
                echo "⚠️ Ошибка установки версии"
            fi
            ;;
        2)
            new_major=$((MAJOR+1))
            cz bump --set-version "$new_major.0.0"
            ;;
        3)
            new_minor=$((MINOR+1))
            cz bump --set-version "$MAJOR.$new_minor.0"
            ;;
        4)
            new_patch=$((PATCH+1))
            cz bump --set-version "$MAJOR.$MINOR.$new_patch"
            ;;
        *)
            echo "❌ Неверный выбор"
            ;;
    esac
fi

echo ""
echo "✅ commitizen-bump.sh завершён!"
read -p "Нажмите Enter чтобы закрыть окно..."
