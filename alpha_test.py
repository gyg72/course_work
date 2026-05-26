import secrets
import string
import math


def get_char_pool(complexity):
    """Возвращает набор символов в зависимости от уровня сложности."""
    if complexity == "лёгкий":
        return string.ascii_lowercase + string.digits
    elif complexity == "средний":
        return string.ascii_letters + string.digits
    elif complexity == "сложный":
        return string.ascii_letters + string.digits + string.punctuation
    else:
        raise ValueError("Допустимые уровни: лёгкий, средний, сложный")

def get_length_range(complexity):
    """Возвращает (мин_длина, макс_длина) для заданного уровня."""
    ranges = {
        "лёгкий": (6, 8),
        "средний": (10, 12),
        "сложный": (14, 16)
    }
    return ranges.get(complexity, (8, 8))

def generate_password(complexity):
    char_pool = get_char_pool(complexity)
    min_len, max_len = get_length_range(complexity)
    length = secrets.randbelow(max_len - min_len + 1) + min_len


    password_chars = [secrets.choice(char_pool) for _ in range(length)]
    return ''.join(password_chars)

def calculate_entropy(password):
    pool_size = 0
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(c in string.punctuation for c in password):
        pool_size += len(string.punctuation)

    if pool_size == 0:
        return 0.0
    return len(password) * math.log2(pool_size)

def check_password_strength(password):
    entropy = calculate_entropy(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)
    types_count = sum([has_lower, has_upper, has_digit, has_special])

    strength = "низкая"
    recommendations = []

    if len(password) < 8:
        recommendations.append("Увеличьте длину хотя бы до 8 символов")
    if types_count < 2:
        recommendations.append("Используйте разные типы символов: цифры, заглавные буквы, спецсимволы")
    if entropy < 40:
        strength = "низкая"
        recommendations.append("Энтропия слишком мала – пароль легко подобрать")
    elif 40 <= entropy <= 60:
        strength = "средняя"
        if types_count < 3:
            recommendations.append("Добавьте ещё один тип символов для надёжности")
        if len(password) < 10:
            recommendations.append("Увеличьте длину до 10+ символов")
    else:  # entropy > 60
        if types_count == 4 and len(password) >= 12:
            strength = "высокая"
            recommendations.append("Отличный пароль!")
        else:
            strength = "высокая (с оговорками)"
            if types_count < 4:
                recommendations.append("Для максимальной безопасности добавьте спецсимволы")
            if len(password) < 12:
                recommendations.append("Длина хорошая, но 12+ надёжнее")

    return strength, round(entropy, 1), recommendations

# ------------------ ОСНОВНАЯ ЛОГИКА ПРОГРАММЫ ------------------
def main():
    print("=" * 50)
    print("   ГЕНЕРАТОР И ПРОВЕРКА ПАРОЛЕЙ")
    print("   (с расчётом энтропии)")
    print("=" * 50)

    while True:
        print("\nВыберите действие:")
        print("1 — Сгенерировать пароль")
        print("2 — Проверить свой пароль")
        print("3 — Выйти")

        choice = input("Ваш выбор: ").strip()

        if choice == "1":
            print("\nУровни сложности: лёгкий, средний, сложный")
            level = input("Введите уровень: ").strip().lower()
            if level not in ("лёгкий", "средний", "сложный"):
                print("Ошибка: неверный уровень. Используйте: лёгкий/средний/сложный")
                continue

            pwd = generate_password(level)
            strength, entropy, recs = check_password_strength(pwd)

            print(f"\nСгенерированный пароль: {pwd}")
            print(f"Сложность: {strength}")
            print(f"Энтропия: {entropy} бит")
            print("Рекомендации:")
            for r in recs:
                print(f"  {r}")

        elif choice == "2":
            pwd = input("\nВведите пароль для проверки: ")
            strength, entropy, recs = check_password_strength(pwd)

            print(f"\nОценка сложности: {strength}")
            print(f"Энтропия: {entropy} бит")
            print("Рекомендации:")
            for r in recs:
                print(f"  {r}")

        elif choice == "3":
            print("До свидания!")
            break
        else:
            print("Неверный ввод, попробуйте снова.")

if __name__ == "__main__":
    main()