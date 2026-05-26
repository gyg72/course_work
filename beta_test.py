import tkinter as tk
from tkinter import ttk, messagebox
import secrets
import string
import math

# ------------------ БАЗОВЫЕ НАБОРЫ СИМВОЛОВ ------------------
CHAR_SETS = {
    "цифры": string.digits,
    "заглавные": string.ascii_uppercase,
    "строчные": string.ascii_lowercase,
    "спецсимволы": string.punctuation
}


# ------------------ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ------------------
def calculate_entropy(password, char_pool_size):
    return len(password) * math.log2(char_pool_size) if char_pool_size > 0 else 0


def get_password_strength(entropy):
    if entropy >= 80:
        return "Очень высокая", "#27ae60"
    elif entropy >= 60:
        return "Высокая", "#2ecc71"
    elif entropy >= 40:
        return "Средняя", "#f39c12"
    else:
        return "Низкая", "#e74c3c"


def get_char_pool_from_choices(choices):
    pool = ""
    for choice in choices:
        if choice in CHAR_SETS:
            pool += CHAR_SETS[choice]
    return pool


def generate_password_from_pool(length, char_pool, mandatory_categories):
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


def check_password_strength(password):
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
        "recommendations": recommendations
    }


# ------------------ ГРАФИЧЕСКОЕ ПРИЛОЖЕНИЕ ------------------
class PasswordApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Генератор и Проверка Паролей")
        self.root.geometry("700x600")
        self.root.resizable(True, True)

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

        self.setup_generate_tab()
        self.setup_check_tab()

    def setup_generate_tab(self):
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

        # Информация о пароле
        self.info_text = tk.Text(result_frame, height=8, wrap="word", font=("Arial", 10),
                                 bg="white", relief="sunken")
        self.info_text.pack(fill="both", expand=True, padx=10, pady=10)

    def setup_check_tab(self):
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

        self.result_text = tk.Text(result_frame, height=15, wrap="word", font=("Arial", 10),
                                   bg="white", relief="sunken")
        self.result_text.pack(fill="both", expand=True, padx=10, pady=10)

    def generate_password(self):
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
            messagebox.showinfo("Успех", "Пароль скопирован в буфер обмена!")

    def check_password(self):
        password = self.check_password_var.get()
        if not password:
            messagebox.showwarning("Предупреждение", "Введите пароль для проверки!")
            return

        analysis = check_password_strength(password)
        strength, color = get_password_strength(analysis["entropy"])

        self.result_text.config(state="normal")
        self.result_text.delete(1.0, tk.END)

        self.result_text.insert(tk.END, f"Пароль: {password}\n\n")
        self.result_text.insert(tk.END, f"Длина: {len(password)} символов\n")
        self.result_text.insert(tk.END, f"Энтропия: {analysis['entropy']} бит\n")
        self.result_text.insert(tk.END, f"Сложность: {strength}\n\n")

        if analysis["used_categories"]:
            self.result_text.insert(tk.END, f"Использованные типы: {', '.join(analysis['used_categories'])}\n\n")
        else:
            self.result_text.insert(tk.END, "Не использовано ни одного типа символов!\n\n")

        if analysis["recommendations"]:
            self.result_text.insert(tk.END, "РЕКОМЕНДАЦИИ:\n")
            for r in analysis["recommendations"]:
                self.result_text.insert(tk.END, f"  • {r}\n")
        else:
            self.result_text.insert(tk.END, "Отличный пароль! Так держать!")

        self.result_text.config(state="disabled")

    def toggle_show_password(self):
        if self.check_entry.cget("show") == "*":
            self.check_entry.config(show="")
            self.show_btn.config(text="Скрыть пароль")
        else:
            self.check_entry.config(show="*")
            self.show_btn.config(text="Показать пароль")

    def clear_check(self):
        self.check_password_var.set("")
        self.result_text.config(state="normal")
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state="disabled")
        self.check_entry.config(show="*")
        self.show_btn.config(text="Показать пароль")


# Запуск приложения
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordApp(root)
    root.mainloop()