import tkinter as tk
from tkinter import ttk, messagebox
import secrets
import string
import math
import json
import os
import hashlib
from datetime import datetime

#БАЗОВЫЕ НАБОРЫ СИМВОЛОВ
CHAR_SETS = {
    "цифры": string.digits,
    "заглавные": string.ascii_uppercase,
    "строчные": string.ascii_lowercase,
    "спецсимволы": string.punctuation
}

# Имя файла для хранения данных справочника
DATA_FILE = "passwords.json"
HASH_FILE = "passwords.hash"


# ------------------ ФУНКЦИИ ДЛЯ РАБОТЫ С ХЭШАМИ ------------------
def calculate_hash(data):#Вычисляет SHA-256 хэш для проверки целостности данных.
    if isinstance(data, (dict, list)):
        json_str = json.dumps(data, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(json_str.encode('utf-8')).hexdigest()
    else:
        return hashlib.sha256(str(data).encode('utf-8')).hexdigest()


def save_hash(data):#Сохраняет хэш данных в отдельный файл.
    hash_value = calculate_hash(data)
    with open(HASH_FILE, 'w', encoding='utf-8') as f:
        f.write(hash_value)
    return hash_value


def verify_hash(data):#Проверяет, соответствуют ли текущие данные сохранённому ранее хэшу.
    if not os.path.exists(HASH_FILE):
        return True, None, None  # Нет файла хэша - считаем валидным

    try:
        with open(HASH_FILE, 'r', encoding='utf-8') as f:
            stored_hash = f.read().strip()

        current_hash = calculate_hash(data)
        return current_hash == stored_hash, stored_hash, current_hash
    except Exception:
        return False, None, None


# ------------------ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ------------------
def calculate_entropy(password, char_pool_size):# Калькулятор энтропии
    if char_pool_size > 0:
        entropy = len(password) * math.log2(char_pool_size)
        return entropy
    else:
        return 0


def get_password_strength(entropy):# Оценка уровня энтропии
    if entropy >= 80:
        return "Очень высокая", "#27ae60"
    elif entropy >= 60:
        return "Высокая", "#2ecc71"
    elif entropy >= 40:
        return "Средняя", "#f39c12"
    else:
        return "Низкая", "#e74c3c"


def get_char_pool_from_choices(choices):# Формирует строку со всеми разрешёнными символами
                                        # на основе выбранных пользователем категорий.
    pool = ""
    for choice in choices:
        if choice in CHAR_SETS:
            pool += CHAR_SETS[choice]
    return pool


def generate_password_from_pool(length, char_pool, mandatory_categories):#Генерирует пароль заданной длины
                                    # с гарантированным включением символов из обязательных категорий.
    if not char_pool:
        raise ValueError("Не выбран ни один тип символов")

    if not mandatory_categories:
        return ''.join(secrets.choice(char_pool) for _ in range(length))

    password_chars = []
    for category in mandatory_categories:
        category_pool = CHAR_SETS[category]
        password_chars.append(secrets.choice(category_pool))


    remaining_length = length - len(password_chars)
    if remaining_length < 0:
        raise ValueError(
            f"Длина пароля ({length}) меньше количества обязательных категорий ({len(mandatory_categories)})")

    for _ in range(remaining_length):
        password_chars.append(secrets.choice(char_pool))

    for i in range(len(password_chars)):
        j = secrets.randbelow(len(password_chars))
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return ''.join(password_chars)


def check_password_strength(password):# Проводит анализ пароля и возвращает все характеристики.
    has_digit = any(c.isdigit() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_special = any(c in string.punctuation for c in password)

    used_categories = []
    pool_size = 0
    if has_digit:
        used_categories.append("цифры")
        pool_size += 10
    if has_upper:
        used_categories.append("заглавные")
        pool_size += 26
    if has_lower:
        used_categories.append("строчные")
        pool_size += 26
    if has_special:
        used_categories.append("спецсимволы")
        pool_size += len(string.punctuation)

    entropy = calculate_entropy(password, pool_size) if pool_size > 0 else 0

    recommendations = []
    if len(password) < 8:
        recommendations.append("Увеличьте длину пароля до 8+ символов")
    if not has_digit:
        recommendations.append("Добавьте цифры")
    if not has_upper:
        recommendations.append("Добавьте заглавные буквы")
    if not has_lower:
        recommendations.append("Добавьте строчные буквы")
    if not has_special:
        recommendations.append("Добавьте спецсимволы (!@#$% и т.п.)")

    return {
        "entropy": round(entropy, 1),
        "used_categories": used_categories,
        "recommendations": recommendations,
        "has_digit": has_digit,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_special": has_special,
        "length": len(password)
    }


def suggest_improved_passwords(original, analysis):# Генерирует три варианта улучшенного пароля
    improved_passwords = []

    missing_categories = []
    if not analysis["has_digit"]:
        missing_categories.append("цифры")
    if not analysis["has_upper"]:
        missing_categories.append("заглавные")
    if not analysis["has_lower"]:
        missing_categories.append("строчные")
    if not analysis["has_special"]:
        missing_categories.append("спецсимволы")

    # Вариант 1: Добавляем недостающие типы символов
    variant1 = original
    for cat in missing_categories:
        variant1 += secrets.choice(CHAR_SETS[cat])

    while len(variant1) < 10:
        all_chars = string.ascii_letters + string.digits + string.punctuation
        variant1 += secrets.choice(all_chars)

    v1_list = list(variant1)
    for i in range(len(v1_list)):
        j = secrets.randbelow(len(v1_list))
        v1_list[i], v1_list[j] = v1_list[j], v1_list[i]
    variant1 = ''.join(v1_list)
    improved_passwords.append(variant1[:16])

    # Вариант 2: Создаём пароль со всеми типами символов
    all_categories = ["цифры", "заглавные", "строчные", "спецсимволы"]
    full_pool = get_char_pool_from_choices(all_categories)

    base = original[:min(6, len(original))]
    for cat in all_categories:
        if cat not in analysis["used_categories"]:
            base += secrets.choice(CHAR_SETS[cat])

    while len(base) < 12:
        base += secrets.choice(full_pool)

    v2_list = list(base)
    for i in range(len(v2_list)):
        j = secrets.randbelow(len(v2_list))
        v2_list[i], v2_list[j] = v2_list[j], v2_list[i]
    variant2 = ''.join(v2_list)
    improved_passwords.append(variant2[:16])

    # Вариант 3: Полностью новый пароль
    target_length = max(12, analysis["length"] + 4)
    variant3 = generate_password_from_pool(target_length, full_pool, all_categories)
    improved_passwords.append(variant3[:16])

    return improved_passwords


# ------------------ КЛАСС ДЛЯ РАБОТЫ СО СПРАВОЧНИКОМ ------------------
class PasswordManager:# Управляет хранением, загрузкой и операциями со справочником паролей.
    def __init__(self, filename=DATA_FILE):# Инициализирует менеджер паролей.
        self.filename = filename
        self.hash_file = HASH_FILE
        self.data = []
        self.load_data()

    def load_data(self):# Загружает данные из JSON-файла и проверяет их целостность.
        if os.path.exists(self.filename):
            try:
                with open(self.filename, 'r', encoding='utf-8') as f:
                    self.data = json.load(f)

                is_valid, stored_hash, current_hash = verify_hash(self.data)

                if not is_valid and stored_hash is not None:
                    print(f"Предупреждение: Файл {self.filename} был изменён!")
                    print(f"Сохранённый хэш: {stored_hash}")
                    print(f"Текущий хэш: {current_hash}")
                    return False

                # Сохраняем/обновляем хэш
                else:
                    save_hash(self.data)
                    return True

            except (json.JSONDecodeError, IOError) as e:
                print(f"Ошибка загрузки: {e}")
                self.data = []
                return False
        else:
            self.data = []
            return True

    def save_data(self):
        with open(self.filename, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)

        # Сохраняем хэш данных
        save_hash(self.data)

    def verify_integrity(self): #Проверяет целостность данных без загрузки.
        if not os.path.exists(self.filename):
            return True, "Файл данных не существует"

        try:
            with open(self.filename, 'r', encoding='utf-8') as f:
                data = json.load(f)

            is_valid, stored_hash, current_hash = verify_hash(data)

            if is_valid:
                return True, "Целостность данных подтверждена"
            else:
                return False, f"Нарушена целостность!\nСохранённый хэш: {stored_hash[:16]}...\nТекущий хэш: {current_hash[:16]}..."
        except Exception as e:
            return False, f"Ошибка проверки: {e}"

    def add_entry(self, service, login, password):# Добавляет новую запись.
        entry = {
            "id": len(self.data) + 1,
            "service": service,
            "login": login,
            "password": password,
            "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.data.append(entry)
        self.save_data()
        return entry

    def delete_entry(self, index):# Удаляет запись по индексу.
        if 0 <= index < len(self.data):
            del self.data[index]
            # Перенумеровываем ID
            for i, entry in enumerate(self.data):
                entry["id"] = i + 1
            self.save_data()
            return True
        else:
            return False

    def update_entry(self, index, service, login, password):# Обновляет существующую запись.
        if 0 <= index < len(self.data):
            self.data[index]["service"] = service
            self.data[index]["login"] = login
            self.data[index]["password"] = password
            self.data[index]["updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.save_data()
            return True
        else:
            return False

    def search(self, query):# Поиск записей по названию сервиса или логину.
        query_lower = query.lower()

        results = []
        for entry in self.data:
            match_service = query_lower in entry["service"].lower()
            match_login = query_lower in entry["login"].lower()

            if match_service or match_login:
                results.append(entry)

        return results

    def get_all(self):# Возвращает все записи.
        return self.data


# ------------------ ГРАФИЧЕСКОЕ ПРИЛОЖЕНИЕ ------------------
class PasswordApp:# Графический интерфейс и обработка действий пользователя.
    def __init__(self, root):# Инициализирует главное окно приложения.
        self.root = root
        self.root.title("Генератор и Проверка Паролей (с защитой целостности)")
        self.root.geometry("900x800")
        self.root.resizable(True, True)

        # Инициализация менеджера паролей
        self.manager = PasswordManager()

        # Стили
        self.root.configure(bg="#f0f0f0")

        # Создание вкладок
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Вкладка генерации
        self.generate_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.generate_frame, text="Генерация пароля")

        # Вкладка проверки
        self.check_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.check_frame, text="Проверка пароля")

        # Вкладка справочника
        self.storage_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.storage_frame, text="Справочник паролей")

        self.setup_generate_tab()
        self.setup_check_tab()
        self.setup_storage_tab()

        # Добавляем кнопку проверки целостности
        self.setup_integrity_button()

    def setup_integrity_button(self):# Добавляет кнопку проверки целостности данных
        integrity_frame = tk.Frame(self.root, bg="#f0f0f0")
        integrity_frame.pack(side="bottom", fill="x", padx=10, pady=5)

        self.integrity_btn = tk.Button(integrity_frame, text="Проверить целостность данных",
                                       command=self.check_integrity,
                                       bg="#95a5a6", fg="white", font=("Arial", 9))
        self.integrity_btn.pack(side="right", padx=5)

        self.integrity_status = tk.Label(integrity_frame, text="Система готова",
                                         bg="#f0f0f0", font=("Arial", 9))
        self.integrity_status.pack(side="left", padx=5)

    def check_integrity(self):# Проверяет целостность файла данных
        is_valid, message = self.manager.verify_integrity()

        if is_valid:
            self.integrity_status.config(text="✅ " + message, fg="#27ae60")
            messagebox.showinfo("Проверка целостности",
                                f"{message}\n\nФайл паролей не был изменён.")
        else:
            self.integrity_status.config(text="❌ " + message, fg="#e74c3c")
            result = messagebox.askquestion("Нарушение целостности!",
                                            f"{message}\n\n"
                                            "ВНИМАНИЕ! Файл паролей был изменён извне.\n"
                                            "Это может указывать на попытку взлома или повреждение данных.\n\n"
                                            "Желаете перезагрузить данные из файла?")
            if result == 'yes':
                self.manager.load_data()
                self.refresh_listbox()
                self.integrity_status.config(text="Данные перезагружены", fg="#27ae60")

    def setup_generate_tab(self):# Создаёт интерфейс вкладки генерации пароля
        # Рамка настроек
        settings_frame = tk.LabelFrame(self.generate_frame, text="Настройки пароля",
                                       bg="#f0f0f0", font=("Arial", 12, "bold"))
        settings_frame.pack(fill="x", padx=20, pady=10)

        # Длина пароля
        tk.Label(settings_frame, text="Длина пароля:", bg="#f0f0f0",
                 font=("Arial", 10)).grid(row=0, column=0, sticky="w", padx=10, pady=10)
        self.length_var = tk.IntVar(value=12)
        length_spinbox = tk.Spinbox(settings_frame, from_=4, to=32, textvariable=self.length_var,
                                    width=10, font=("Arial", 10))
        length_spinbox.grid(row=0, column=1, sticky="w", padx=10, pady=10)

        tk.Label(settings_frame, text="(4-32 символа)", bg="#f0f0f0",
                 font=("Arial", 8, "italic")).grid(row=0, column=2, sticky="w", padx=5, pady=10)

        # Типы символов
        tk.Label(settings_frame, text="Типы символов:", bg="#f0f0f0",
                 font=("Arial", 10)).grid(row=1, column=0, sticky="nw", padx=10, pady=10)

        self.use_digits = tk.BooleanVar(value=True)
        self.use_uppercase = tk.BooleanVar(value=True)
        self.use_lowercase = tk.BooleanVar(value=True)
        self.use_special = tk.BooleanVar(value=True)

        tk.Checkbutton(settings_frame, text="Цифры (0-9)", variable=self.use_digits,
                       bg="#f0f0f0", font=("Arial", 10)).grid(row=1, column=1, sticky="w", padx=10, pady=5)
        tk.Checkbutton(settings_frame, text="Заглавные буквы (A-Z)", variable=self.use_uppercase,
                       bg="#f0f0f0", font=("Arial", 10)).grid(row=2, column=1, sticky="w", padx=10, pady=5)
        tk.Checkbutton(settings_frame, text="Строчные буквы (a-z)", variable=self.use_lowercase,
                       bg="#f0f0f0", font=("Arial", 10)).grid(row=3, column=1, sticky="w", padx=10, pady=5)
        tk.Checkbutton(settings_frame, text="Спецсимволы (!@#$...)", variable=self.use_special,
                       bg="#f0f0f0", font=("Arial", 10)).grid(row=4, column=1, sticky="w", padx=10, pady=5)

        # Кнопка генерации
        self.generate_btn = tk.Button(self.generate_frame, text="Сгенерировать пароль",
                                      command=self.generate_password,
                                      bg="#3498db", fg="white", font=("Arial", 12, "bold"),
                                      padx=20, pady=10)
        self.generate_btn.pack(pady=20)

        # Результат
        result_frame = tk.LabelFrame(self.generate_frame, text="Результат",
                                     bg="#f0f0f0", font=("Arial", 12, "bold"))
        result_frame.pack(fill="both", expand=True, padx=20, pady=10)

        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(result_frame, textvariable=self.password_var,
                                       font=("Courier", 14), justify="center",
                                       state="readonly", readonlybackground="white")
        self.password_entry.pack(fill="x", padx=10, pady=10)

        # Кнопка копирования
        self.copy_btn = tk.Button(result_frame, text="Копировать", command=self.copy_password,
                                  bg="#2ecc71", fg="white", font=("Arial", 10))
        self.copy_btn.pack(pady=5)

        # Кнопка сохранения в справочник
        self.save_to_storage_btn = tk.Button(result_frame, text="Сохранить в справочник",
                                             command=self.save_generated_to_storage,
                                             bg="#9b59b6", fg="white", font=("Arial", 10))
        self.save_to_storage_btn.pack(pady=5)

        # Информация о пароле
        self.info_text = tk.Text(result_frame, height=8, wrap="word", font=("Arial", 10),
                                 bg="white", relief="sunken")
        self.info_text.pack(fill="both", expand=True, padx=10, pady=10)

    def setup_check_tab(self):#Создаёт интерфейс вкладки проверки пароля
        # Ввод пароля
        input_frame = tk.LabelFrame(self.check_frame, text="Введите пароль для проверки",
                                    bg="#f0f0f0", font=("Arial", 12, "bold"))
        input_frame.pack(fill="x", padx=20, pady=10)

        self.check_password_var = tk.StringVar()
        self.check_entry = tk.Entry(input_frame, textvariable=self.check_password_var,
                                    font=("Courier", 12), show="*")
        self.check_entry.pack(fill="x", padx=10, pady=10)

        # Кнопки показа/скрытия и проверки
        btn_frame = tk.Frame(input_frame, bg="#f0f0f0")
        btn_frame.pack(pady=10)

        self.show_btn = tk.Button(btn_frame, text="Показать пароль", command=self.toggle_show_password,
                                  bg="#95a5a6", fg="white", font=("Arial", 10))
        self.show_btn.pack(side="left", padx=5)

        self.check_btn = tk.Button(btn_frame, text="Проверить", command=self.check_password,
                                   bg="#3498db", fg="white", font=("Arial", 10, "bold"))
        self.check_btn.pack(side="left", padx=5)

        self.clear_btn = tk.Button(btn_frame, text="Очистить", command=self.clear_check,
                                   bg="#e74c3c", fg="white", font=("Arial", 10))
        self.clear_btn.pack(side="left", padx=5)

        # Результат проверки
        result_frame = tk.LabelFrame(self.check_frame, text="Результат проверки",
                                     bg="#f0f0f0", font=("Arial", 12, "bold"))
        result_frame.pack(fill="both", expand=True, padx=20, pady=10)

        # Создаём текстовое поле с прокруткой
        text_frame = tk.Frame(result_frame, bg="#f0f0f0")
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)

        scrollbar = tk.Scrollbar(text_frame)
        scrollbar.pack(side="right", fill="y")

        self.result_text = tk.Text(text_frame, height=20, wrap="word", font=("Arial", 10),
                                   bg="white", relief="sunken", yscrollcommand=scrollbar.set)
        self.result_text.pack(fill="both", expand=True)
        scrollbar.config(command=self.result_text.yview)

        # Добавляем теги для форматирования
        self.result_text.tag_config("bold", font=("Arial", 11, "bold"))
        self.result_text.tag_config("password", font=("Courier", 10))

    def setup_storage_tab(self):# Создаёт интерфейс вкладки справочника паролей
        # Верхняя панель с кнопками
        top_frame = tk.Frame(self.storage_frame, bg="#f0f0f0")
        top_frame.pack(fill="x", padx=20, pady=10)

        # Кнопки управления
        self.add_btn = tk.Button(top_frame, text="➕ Добавить запись", command=self.add_entry_dialog,
                                 bg="#2ecc71", fg="white", font=("Arial", 10, "bold"))
        self.add_btn.pack(side="left", padx=5)

        self.edit_btn = tk.Button(top_frame, text="Редактировать", command=self.edit_entry_dialog,
                                  bg="#3498db", fg="white", font=("Arial", 10, "bold"))
        self.edit_btn.pack(side="left", padx=5)

        self.delete_btn = tk.Button(top_frame, text="Удалить", command=self.delete_entry,
                                    bg="#e74c3c", fg="white", font=("Arial", 10, "bold"))
        self.delete_btn.pack(side="left", padx=5)

        # Поиск
        tk.Label(top_frame, text="Поиск:", bg="#f0f0f0", font=("Arial", 10)).pack(side="left", padx=(20, 5))
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(top_frame, textvariable=self.search_var, width=20, font=("Arial", 10))
        self.search_entry.pack(side="left", padx=5)
        self.search_btn = tk.Button(top_frame, text="Найти", command=self.search_entries,
                                    bg="#95a5a6", fg="white", font=("Arial", 10))
        self.search_btn.pack(side="left", padx=5)
        self.show_all_btn = tk.Button(top_frame, text="Показать все", command=self.refresh_listbox,
                                      bg="#9b59b6", fg="white", font=("Arial", 10))
        self.show_all_btn.pack(side="left", padx=5)

        # Рамка для списка записей
        list_frame = tk.LabelFrame(self.storage_frame, text="Сохранённые записи",
                                   bg="#f0f0f0", font=("Arial", 12, "bold"))
        list_frame.pack(fill="both", expand=True, padx=20, pady=10)

        # Создаём фрейм для списка и скроллбара
        list_inner_frame = tk.Frame(list_frame, bg="#f0f0f0")
        list_inner_frame.pack(fill="both", expand=True, padx=10, pady=10)

        scrollbar = tk.Scrollbar(list_inner_frame)
        scrollbar.pack(side="right", fill="y")

        self.entries_listbox = tk.Listbox(list_inner_frame, yscrollcommand=scrollbar.set,
                                          font=("Arial", 10), height=15)
        self.entries_listbox.pack(fill="both", expand=True)
        scrollbar.config(command=self.entries_listbox.yview)

        # Привязываем событие выбора
        self.entries_listbox.bind('<<ListboxSelect>>', self.on_select_entry)

        # Рамка для деталей выбранной записи
        details_frame = tk.LabelFrame(self.storage_frame, text="Детали записи",
                                      bg="#f0f0f0", font=("Arial", 12, "bold"))
        details_frame.pack(fill="x", padx=20, pady=10)

        # Поля для отображения деталей
        details_inner = tk.Frame(details_frame, bg="#f0f0f0")
        details_inner.pack(fill="x", padx=10, pady=10)

        tk.Label(details_inner, text="Сервис:", bg="#f0f0f0", font=("Arial", 10, "bold")).grid(row=0, column=0,
                                                                                               sticky="w", padx=5,
                                                                                               pady=5)
        self.detail_service = tk.Label(details_inner, text="", bg="#f0f0f0", font=("Arial", 10))
        self.detail_service.grid(row=0, column=1, sticky="w", padx=5, pady=5)

        tk.Label(details_inner, text="Логин:", bg="#f0f0f0", font=("Arial", 10, "bold")).grid(row=1, column=0,
                                                                                              sticky="w", padx=5,
                                                                                              pady=5)
        self.detail_login = tk.Label(details_inner, text="", bg="#f0f0f0", font=("Arial", 10))
        self.detail_login.grid(row=1, column=1, sticky="w", padx=5, pady=5)

        # Кнопка копирования логина
        self.copy_login_btn = tk.Button(details_inner, text="Копировать логин",
                                        command=self.copy_login_from_detail,
                                        bg="#3498db", fg="white", font=("Arial", 8))
        self.copy_login_btn.grid(row=1, column=2, padx=10)

        tk.Label(details_inner, text="Пароль:", bg="#f0f0f0", font=("Arial", 10, "bold")).grid(row=2, column=0,
                                                                                               sticky="w", padx=5,
                                                                                               pady=5)
        self.detail_password = tk.Label(details_inner, text="", bg="#f0f0f0", font=("Courier", 10))
        self.detail_password.grid(row=2, column=1, sticky="w", padx=5, pady=5)

        # Кнопки для работы с паролем
        button_frame = tk.Frame(details_inner, bg="#f0f0f0")
        button_frame.grid(row=2, column=2, padx=10)

        self.show_password_btn = tk.Button(button_frame, text="Показать",
                                           command=self.toggle_detail_password,
                                           bg="#95a5a6", fg="white", font=("Arial", 8))
        self.show_password_btn.pack(side="left", padx=2)

        self.copy_password_btn = tk.Button(button_frame, text="Копировать",
                                           command=self.copy_password_from_detail,
                                           bg="#2ecc71", fg="white", font=("Arial", 8))
        self.copy_password_btn.pack(side="left", padx=2)

        tk.Label(details_inner, text="Создано:", bg="#f0f0f0", font=("Arial", 10, "bold")).grid(row=3, column=0,
                                                                                                sticky="w", padx=5,
                                                                                                pady=5)
        self.detail_created = tk.Label(details_inner, text="", bg="#f0f0f0", font=("Arial", 10))
        self.detail_created.grid(row=3, column=1, sticky="w", padx=5, pady=5)

        # Переменная для хранения текущего выбранного индекса
        self.current_selection = None
        self.password_visible = False

        # Загружаем данные
        self.refresh_listbox()

    def generate_password(self):#Обрабатывает нажатие кнопки "Сгенерировать пароль"
        length = self.length_var.get()

        categories = []
        if self.use_digits.get():
            categories.append("цифры")
        if self.use_uppercase.get():
            categories.append("заглавные")
        if self.use_lowercase.get():
            categories.append("строчные")
        if self.use_special.get():
            categories.append("спецсимволы")

        if not categories:
            messagebox.showwarning("Предупреждение", "Выберите хотя бы один тип символов!")
            return

        if length < len(categories):
            messagebox.showwarning("Предупреждение",
                                   f"Длина пароля ({length}) меньше количества выбранных типов символов ({len(categories)})!\n"
                                   f"Будет увеличена до {len(categories)}")
            length = len(categories)
            self.length_var.set(length)

        char_pool = get_char_pool_from_choices(categories)

        try:
            password = generate_password_from_pool(length, char_pool, categories)
            self.password_var.set(password)

            # Обновляем информацию
            pool_size = len(char_pool)
            entropy = calculate_entropy(password, pool_size)
            strength, color = get_password_strength(entropy)

            self.info_text.config(state="normal")
            self.info_text.delete(1.0, tk.END)
            self.info_text.insert(tk.END, f"Длина: {len(password)} символов\n")
            self.info_text.insert(tk.END, f"Использованные типы: {', '.join(categories)}\n")
            self.info_text.insert(tk.END, f"Размер алфавита: {pool_size} символов\n")
            self.info_text.insert(tk.END, f"Энтропия: {entropy:.1f} бит\n")
            self.info_text.insert(tk.END, f"Сложность: {strength}")
            self.info_text.config(state="disabled")

            # Подсветка результата
            self.password_entry.config(bg="lightyellow")
            self.root.after(2000, lambda: self.password_entry.config(bg="white"))

        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def copy_password(self):
        password = self.password_var.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Успех", "Пароль скопирован в буфер обмена")

    def copy_login_from_detail(self):# Копирует логин
        if not self.current_selection:
            messagebox.showwarning("Предупреждение", "Выберите запись для копирования логина")
            return

        login = self.current_selection["login"]
        self.root.clipboard_clear()
        self.root.clipboard_append(login)
        messagebox.showinfo("Успех",
                            f"Логин для сервиса '{self.current_selection['service']}' скопирован в буфер обмена")

    def copy_password_from_detail(self):# Копирует пароль
        if not self.current_selection:
            messagebox.showwarning("Предупреждение", "Выберите запись для копирования пароля")
            return

        password = self.current_selection["password"]
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        messagebox.showinfo("Успех",
                            f"Пароль для сервиса '{self.current_selection['service']}' скопирован в буфер обмена")

    def copy_improved_password(self, password, variant_num):#Копирует улучшенную версию пароля
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        messagebox.showinfo("Успех", f"Улучшенный пароль (вариант {variant_num}) скопирован в буфер обмена")

    def save_generated_to_storage(self):#Сохраняет сгенерированный пароль в справочник
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Предупреждение", "Сначала сгенерируйте пароль")
            return

        # Диалог для ввода названия сервиса и логина
        dialog = tk.Toplevel(self.root)
        dialog.title("Сохранение пароля")
        dialog.geometry("400x300")
        dialog.configure(bg="#f0f0f0")
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text="Название сервиса:", bg="#f0f0f0", font=("Arial", 10)).pack(pady=(20, 5))
        service_entry = tk.Entry(dialog, width=40, font=("Arial", 10))
        service_entry.pack(pady=5)

        tk.Label(dialog, text="Логин/Email:", bg="#f0f0f0", font=("Arial", 10)).pack(pady=5)
        login_entry = tk.Entry(dialog, width=40, font=("Arial", 10))
        login_entry.pack(pady=5)

        tk.Label(dialog, text=f"Пароль: {password}", bg="#f0f0f0", font=("Courier", 10)).pack(pady=10)

        def save():# Проверка на ввод данных
            service = service_entry.get().strip()
            login = login_entry.get().strip()

            if not service:
                messagebox.showwarning("Предупреждение", "Введите название сервиса")
                return
            if not login:
                messagebox.showwarning("Предупреждение", "Введите логин")
                return

            self.manager.add_entry(service, login, password)
            self.refresh_listbox()
            dialog.destroy()
            messagebox.showinfo("Успех", "Запись сохранена в справочник")

        tk.Button(dialog, text="Сохранить", command=save, bg="#2ecc71", fg="white",
                  font=("Arial", 10, "bold")).pack(pady=20)

    def check_password(self):# Проверка введён ли пароль
        password = self.check_password_var.get()
        if not password:
            messagebox.showwarning("Предупреждение", "Введите пароль для проверки")
            return

        analysis = check_password_strength(password)
        strength, color = get_password_strength(analysis["entropy"])

        self.result_text.config(state="normal")
        self.result_text.delete(1.0, tk.END)

        # Основная информация
        self.result_text.insert(tk.END, "-" * 50 + "\n", "bold")
        self.result_text.insert(tk.END, "РЕЗУЛЬТАТЫ ПРОВЕРКИ ПАРОЛЯ\n", "bold")
        self.result_text.insert(tk.END, "-" * 50 + "\n\n", "bold")

        self.result_text.insert(tk.END, f"Пароль: {password}\n\n")
        self.result_text.insert(tk.END, f"Длина: {len(password)} символов\n")
        self.result_text.insert(tk.END, f"Энтропия: {analysis['entropy']} бит\n")
        self.result_text.insert(tk.END, f"Сложность: {strength}\n\n")

        if analysis["used_categories"]:
            self.result_text.insert(tk.END, f"Использованные типы: {', '.join(analysis['used_categories'])}\n\n")
        else:
            self.result_text.insert(tk.END, "Не использовано ни одного типа символов!\n\n")

        # Рекомендации
        if analysis["recommendations"]:
            self.result_text.insert(tk.END, "-" * 50 + "\n", "bold")
            self.result_text.insert(tk.END, "РЕКОМЕНДАЦИИ ПО УЛУЧШЕНИЮ:\n", "bold")
            self.result_text.insert(tk.END, "-" * 50 + "\n", "bold")
            for r in analysis["recommendations"]:
                self.result_text.insert(tk.END, f"  • {r}\n")
            self.result_text.insert(tk.END, "\n")

        # Улучшенные версии пароля
        if analysis["recommendations"] or analysis["entropy"] < 60:
            self.result_text.insert(tk.END, "-" * 50 + "\n", "bold")
            self.result_text.insert(tk.END, "УЛУЧШЕННЫЕ ВЕРСИИ ПАРОЛЯ:\n", "bold")
            self.result_text.insert(tk.END, "-" * 50 + "\n\n", "bold")

            improved_passwords = suggest_improved_passwords(password, analysis)

            for i, imp in enumerate(improved_passwords, 1):
                imp_analysis = check_password_strength(imp)
                imp_strength, imp_color = get_password_strength(imp_analysis["entropy"])

                self.result_text.insert(tk.END, f"   Вариант {i}:\n")
                self.result_text.insert(tk.END, f"   Пароль: {imp}\n")
                self.result_text.insert(tk.END, f"   Длина: {len(imp)} символов\n")
                self.result_text.insert(tk.END, f"   Энтропия: {imp_analysis['entropy']} бит\n")
                self.result_text.insert(tk.END, f"   Сложность: {imp_strength}\n")
                if imp_analysis["used_categories"]:
                    self.result_text.insert(tk.END, f"   Типы: {', '.join(imp_analysis['used_categories'])}\n")

                # Добавляем кнопку копирования для улучшенного пароля
                copy_btn_frame = tk.Frame(self.result_text, bg="white")
                self.result_text.window_create(tk.END, window=copy_btn_frame)
                copy_btn = tk.Button(copy_btn_frame, text="Копировать пароль",
                                     command=lambda p=imp, v=i: self.copy_improved_password(p, v),
                                     bg="#2ecc71", fg="white", font=("Arial", 8))
                copy_btn.pack(pady=2)
                self.result_text.insert(tk.END, "\n\n")

            self.result_text.insert(tk.END, " Рекомендация: Выберите один из вариантов или создайте\n")
            self.result_text.insert(tk.END, "   свой пароль по аналогии с предложенными.\n")
        else:
            self.result_text.insert(tk.END, "\n Отличный пароль! Не требует улучшения")

        self.result_text.config(state="disabled")

    def toggle_show_password(self):# Cкрыть пароль
        if self.check_entry.cget("show") == "*":
            self.check_entry.config(show="")
            self.show_btn.config(text="Скрыть пароль")
        else:
            self.check_entry.config(show="*")
            self.show_btn.config(text="Показать пароль")

    def clear_check(self):# Показать пароль
        self.check_password_var.set("")
        self.result_text.config(state="normal")
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state="disabled")
        self.check_entry.config(show="*")
        self.show_btn.config(text="Показать пароль")

    # ------------------ МЕТОДЫ ДЛЯ РАБОТЫ СО СПРАВОЧНИКОМ ------------------
    def refresh_listbox(self):# Обновляет список записей
        self.entries_listbox.delete(0, tk.END)
        entries = self.manager.get_all()
        for entry in entries:
            display_text = f"[{entry['id']}] {entry['service']} - {entry['login']}"
            self.entries_listbox.insert(tk.END, display_text)

    def search_entries(self):# Выполняет поиск записей
        query = self.search_var.get().strip()
        if not query:
            self.refresh_listbox()
            return

        self.entries_listbox.delete(0, tk.END)
        entries = self.manager.search(query)
        for entry in entries:
            display_text = f"[{entry['id']}] {entry['service']} - {entry['login']}"
            self.entries_listbox.insert(tk.END, display_text)

        if not entries:
            messagebox.showinfo("Поиск", "Записи не найдены")

    def on_select_entry(self, event):# Обрабатывает выбор записи в списке
        selection = self.entries_listbox.curselection()
        if not selection:
            return

        index = selection[0]
        entries = self.manager.get_all() if not self.search_var.get() else self.manager.search(self.search_var.get())

        if index < len(entries):
            self.current_selection = entries[index]
            self.password_visible = False

            self.detail_service.config(text=self.current_selection["service"])
            self.detail_login.config(text=self.current_selection["login"])
            self.detail_password.config(text="*" * len(self.current_selection["password"]))
            self.detail_created.config(text=self.current_selection.get("created", "Не указано"))
            self.show_password_btn.config(text="Показать")

    def toggle_detail_password(self):# Показывает или скрывает пароль
        if not self.current_selection:
            return

        if not self.password_visible:
            self.detail_password.config(text=self.current_selection["password"])
            self.show_password_btn.config(text="Скрыть")
            self.password_visible = True
        else:
            self.detail_password.config(text="*" * len(self.current_selection["password"]))
            self.show_password_btn.config(text="Показать")
            self.password_visible = False

    def add_entry_dialog(self):#Открывает вкладку добавления записи
        dialog = tk.Toplevel(self.root)
        dialog.title("Добавление записи")
        dialog.geometry("450x400")
        dialog.configure(bg="#f0f0f0")
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text="Название сервиса:", bg="#f0f0f0", font=("Arial", 10)).pack(pady=(20, 5))
        service_entry = tk.Entry(dialog, width=40, font=("Arial", 10))
        service_entry.pack(pady=5)

        tk.Label(dialog, text="Логин/Email:", bg="#f0f0f0", font=("Arial", 10)).pack(pady=5)
        login_entry = tk.Entry(dialog, width=40, font=("Arial", 10))
        login_entry.pack(pady=5)

        tk.Label(dialog, text="Пароль:", bg="#f0f0f0", font=("Arial", 10)).pack(pady=5)
        password_entry = tk.Entry(dialog, width=40, font=("Courier", 10), show="*")
        password_entry.pack(pady=5)

        # Кнопки для работы с паролем
        pwd_button_frame = tk.Frame(dialog, bg="#f0f0f0")
        pwd_button_frame.pack(pady=5)

        def generate_for_dialog():
            pwd = generate_password_from_pool(12,
                                              string.ascii_letters + string.digits + string.punctuation,
                                              ["цифры", "заглавные", "строчные", "спецсимволы"])
            password_entry.delete(0, tk.END)
            password_entry.insert(0, pwd)

        def toggle_show_pwd():
            if password_entry.cget("show") == "*":
                password_entry.config(show="")
                show_pwd_btn.config(text="Скрыть")
            else:
                password_entry.config(show="*")
                show_pwd_btn.config(text="Показать")

        show_pwd_btn = tk.Button(pwd_button_frame, text="Показать", command=toggle_show_pwd,
                                 bg="#95a5a6", fg="white", font=("Arial", 8))
        show_pwd_btn.pack(side="left", padx=2)

        generate_btn = tk.Button(pwd_button_frame, text="Сгенерировать", command=generate_for_dialog,
                                 bg="#3498db", fg="white", font=("Arial", 8))
        generate_btn.pack(side="left", padx=2)

        def save():
            service = service_entry.get().strip()
            login = login_entry.get().strip()
            password = password_entry.get().strip()

            if not service:
                messagebox.showwarning("Предупреждение", "Введите название сервиса!")
                return
            if not login:
                messagebox.showwarning("Предупреждение", "Введите логин!")
                return
            if not password:
                messagebox.showwarning("Предупреждение", "Введите пароль!")
                return

            self.manager.add_entry(service, login, password)
            self.refresh_listbox()
            dialog.destroy()
            messagebox.showinfo("Успех", "Запись добавлена!")

        tk.Button(dialog, text="Сохранить", command=save, bg="#2ecc71", fg="white",
                  font=("Arial", 10, "bold")).pack(pady=20)

    def edit_entry_dialog(self):# Открывает вкладку редактирования записи
        if not self.current_selection:
            messagebox.showwarning("Предупреждение", "Выберите запись для редактирования!")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Редактирование записи")
        dialog.geometry("450x400")
        dialog.configure(bg="#f0f0f0")
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text="Название сервиса:", bg="#f0f0f0", font=("Arial", 10)).pack(pady=(20, 5))
        service_entry = tk.Entry(dialog, width=40, font=("Arial", 10))
        service_entry.insert(0, self.current_selection["service"])
        service_entry.pack(pady=5)

        tk.Label(dialog, text="Логин/Email:", bg="#f0f0f0", font=("Arial", 10)).pack(pady=5)
        login_entry = tk.Entry(dialog, width=40, font=("Arial", 10))
        login_entry.insert(0, self.current_selection["login"])
        login_entry.pack(pady=5)

        tk.Label(dialog, text="Пароль:", bg="#f0f0f0", font=("Arial", 10)).pack(pady=5)
        password_entry = tk.Entry(dialog, width=40, font=("Courier", 10))
        password_entry.insert(0, self.current_selection["password"])
        password_entry.pack(pady=5)

        def update():# Обновление
            service = service_entry.get().strip()
            login = login_entry.get().strip()
            password = password_entry.get().strip()

            if not service or not login or not password:
                messagebox.showwarning("Предупреждение", "Заполните все поля!")
                return

            entries = self.manager.get_all()
            for i, entry in enumerate(entries):
                if entry["id"] == self.current_selection.get("id"):
                    self.manager.update_entry(i, service, login, password)
                    break

            self.refresh_listbox()
            dialog.destroy()
            messagebox.showinfo("Успех", "Запись обновлена!")

        tk.Button(dialog, text="Обновить", command=update, bg="#3498db", fg="white",
                  font=("Arial", 10, "bold")).pack(pady=20)

    def delete_entry(self):#Удаляет выбранную запись
        if not self.current_selection:
            messagebox.showwarning("Предупреждение", "Выберите запись для удаления!")
            return

        if messagebox.askyesno("Подтверждение",
                               f"Удалить запись для сервиса '{self.current_selection['service']}'?"):
            entries = self.manager.get_all()
            for i, entry in enumerate(entries):
                if entry["id"] == self.current_selection["id"]:
                    self.manager.delete_entry(i)
                    break

            self.current_selection = None
            self.detail_service.config(text="")
            self.detail_login.config(text="")
            self.detail_password.config(text="")
            self.detail_created.config(text="")
            self.refresh_listbox()
            messagebox.showinfo("Успех", "Запись удалена!")


# Запуск приложения
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordApp(root)
    root.mainloop()