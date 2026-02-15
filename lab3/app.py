from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)

# Секретный ключ для работы сессий и подписи cookie
app.secret_key = 'super_secret_key_for_lab'

# Настройка Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
# Указываем страницу, куда перенаправлять, если доступ запрещен
login_manager.login_view = 'login'
# Сообщение, которое увидит пользователь при попытке зайти на защищенную страницу без авторизации
login_manager.login_message = "Для доступа к данной странице необходимо пройти процедуру аутентификации."
login_manager.login_message_category = "warning"

# Эмуляция базы данных пользователей
users_db = {
    "user": {"password": "qwerty"}
}


# Модель пользователя
# Наследуемся от UserMixin, чтобы получить стандартные методы
class User(UserMixin):
    def __init__(self, id):
        self.id = id


# Эта функция нужна Flask-Login, чтобы загружать пользователя из сессии по его ID
@login_manager.user_loader
def load_user(user_id):
    if user_id in users_db:
        return User(user_id)
    return None


@app.route('/')
def index():
    return render_template('index.html')


# Задание 1: Счётчик посещений
@app.route('/counter')
def counter():
    # Проверяем, есть ли ключ 'visits' в глобальном объекте session
    if 'visits' in session:
        session['visits'] += 1
    else:
        session['visits'] = 1  # Инициализируем счетчик при первом визите

    return render_template('counter.html', visits=session['visits'])


# Задание 2: Аутентификация
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Если пользователь уже вошел, перенаправляем на главную
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Получаем значение чекбокса "Запомнить меня"
        if request.form.get('remember'):
            remember = True
        else:
            remember = False

        # Проверка логина и пароля
        if username in users_db and users_db[username]['password'] == password:
            user = User(username)
            # Авторизуем пользователя
            login_user(user, remember=remember)

            flash('Вы успешно вошли в систему!', 'success')

            # Проверяем, есть ли параметр 'next' (страница, куда хотел попасть пользователь)
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)

            return redirect(url_for('index'))
        else:
            flash('Неверный логин или пароль', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))


# Задание 3: Секретная страница
@app.route('/secret')
@login_required  # Декоратор дает доступ только вошедшим
def secret():
    return render_template('secret.html')


if __name__ == '__main__':
    app.run(debug=True)