import re
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Role

app = Flask(__name__)

# Конфигурация
app.config['SECRET_KEY'] = 'secret_key_lab4_final'  # Для сессий и flash-сообщений
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Файл базы данных
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализируем расширения
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Настройки входа
login_manager.login_view = 'login'  # Если не вошел - редирект сюда
login_manager.login_message = "Пожалуйста, войдите для доступа к этой странице."
login_manager.login_message_category = "warning"


@login_manager.user_loader
def load_user(user_id):
    """Загрузка пользователя для сессии Flask-Login"""
    return User.query.get(int(user_id))


# Функции валидации

def validate_user_input(form_data, is_edit=False):
    """
    Проверяет данные формы.
    Возвращает словарь ошибок: {'поле': 'текст ошибки'}.
    """
    errors = {}

    # 1. Проверка ФИО
    if not form_data.get('last_name'):
        errors['last_name'] = 'Поле не может быть пустым'
    if not form_data.get('first_name'):
        errors['first_name'] = 'Поле не может быть пустым'

    # Отчество необязательно, его не проверяем на наличие.

    # 2. Проверка логина (только при создании)
    if not is_edit:
        login = form_data.get('login', '')
        if not login:
            errors['login'] = 'Поле не может быть пустым'
        elif len(login) < 5:
            errors['login'] = 'Логин должен быть не менее 5 символов'
        # Регулярное выражение: только буквы (a-z) и цифры (0-9)
        elif not re.match(r'^[a-zA-Z0-9]+$', login):
            errors['login'] = 'Логин должен состоять только из латинских букв и цифр'
        else:
            # Проверка на уникальность в БД
            if User.query.filter_by(login=login).first():
                errors['login'] = 'Такой логин уже занят'

    # 3. Проверка пароля (только при создании)
    if not is_edit:
        password = form_data.get('password', '')
        pass_error = check_password_requirements(password)
        if pass_error:
            errors['password'] = pass_error

    return errors


def check_password_requirements(password):
    """
    Проверяет корректность пароля.
    Возвращает текст ошибки или None.
    """
    if not password:
        return 'Поле не может быть пустым'

    if not (8 <= len(password) <= 128):
        return 'Длина пароля от 8 до 128 символов'

    if ' ' in password:
        return 'Пароль не должен содержать пробелов'

    # Разрешенные символы: Латиница, Кириллица, Цифры, Спецсимволы
    allowed_pattern = r'^[a-zA-Zа-яА-Я0-9~!@#$%^&*_\-+()\[\]{}><\/\\|"\'. ,:;]+$'
    if not re.match(allowed_pattern, password):
        return 'Пароль содержит недопустимые символы'

    # Проверка состава
    has_upper = any(c.isupper() for c in password)  # Заглавная
    has_lower = any(c.islower() for c in password)  # Строчная
    has_digit = any(c.isdigit() for c in password)  # Цифра

    if not (has_upper and has_lower and has_digit):
        return 'Нужна минимум 1 заглавная, 1 строчная буквы и 1 цифра'

    return None  # Ошибок нет


# Маршруты

# Главная страница: Список пользователей
@app.route('/')
def index():
    users = User.query.order_by(User.id).all()
    return render_template('index.html', users=users)


# Страница входа
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        login_val = request.form.get('login')
        password_val = request.form.get('password')
        remember = True if request.form.get('remember') else False

        user = User.query.filter_by(login=login_val).first()

        if user and check_password_hash(user.password_hash, password_val):
            login_user(user, remember=remember)
            flash('Вы успешно вошли!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверный логин или пароль', 'danger')

    return render_template('login.html')


# Выход из системы
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))


# Просмотр данных пользователя (доступно всем)
@app.route('/users/<int:user_id>')
def user_view(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('user_view.html', user=user)


# Создание пользователя (только для авторизованных)
@app.route('/users/create', methods=['GET', 'POST'])
@login_required
def user_create():
    roles = Role.query.all()

    if request.method == 'POST':
        # Валидация
        errors = validate_user_input(request.form, is_edit=False)

        if errors:
            flash('Ошибка валидации данных.', 'danger')
            return render_template('user_form.html', roles=roles, form_data=request.form,
                                   errors=errors, is_edit=False)

        try:
            # Обработка role_id (если пустая строка - то None)
            role_id = request.form.get('role_id')
            role_id = int(role_id) if role_id else None

            new_user = User(
                login=request.form['login'],
                password_hash=generate_password_hash(request.form['password']),
                last_name=request.form['last_name'],
                first_name=request.form['first_name'],
                middle_name=request.form['middle_name'],
                role_id=role_id
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Пользователь успешно создан!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка БД: {e}', 'danger')

    return render_template('user_form.html', roles=roles, form_data={}, errors={}, is_edit=False)


# Редактирование пользователя
@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def user_edit(user_id):
    user = User.query.get_or_404(user_id)
    roles = Role.query.all()

    if request.method == 'POST':
        # Валидация (без проверки логина/пароля)
        errors = validate_user_input(request.form, is_edit=True)

        if errors:
            flash('Ошибка валидации данных.', 'danger')
            return render_template('user_form.html', roles=roles, form_data=request.form,
                                   errors=errors, is_edit=True, user=user)

        try:
            user.last_name = request.form['last_name']
            user.first_name = request.form['first_name']
            user.middle_name = request.form['middle_name']

            role_id = request.form.get('role_id')
            user.role_id = int(role_id) if role_id else None

            db.session.commit()
            flash('Пользователь обновлен.', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка обновления: {e}', 'danger')

    # Данные для заполнения формы
    form_data = {
        'last_name': user.last_name,
        'first_name': user.first_name,
        'middle_name': user.middle_name,
        'role_id': user.role_id
    }
    return render_template('user_form.html', roles=roles, form_data=form_data,
                           errors={}, is_edit=True, user=user)


# Удаление пользователя
@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def user_delete(user_id):
    user = User.query.get_or_404(user_id)
    try:
        name = user.full_name
        db.session.delete(user)
        db.session.commit()
        flash(f'Пользователь {name} удален.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Ошибка при удалении.', 'danger')

    return redirect(url_for('index'))


# Смена пароля текущего пользователя
@app.route('/account/password', methods=['GET', 'POST'])
@login_required
def change_password():
    errors = {}
    if request.method == 'POST':
        old_pass = request.form.get('old_password')
        new_pass = request.form.get('new_password')
        confirm_pass = request.form.get('confirm_password')

        # 1. Проверка старого пароля
        if not check_password_hash(current_user.password_hash, old_pass):
            errors['old_password'] = 'Старый пароль введен неверно'

        # Старый и новый не должны совпадать
        elif old_pass == new_pass:
            errors['new_password'] = 'Новый пароль не должен совпадать со старым'

        # 2. Требования к новому паролю
        if 'new_password' not in errors:
            pass_err = check_password_requirements(new_pass)
            if pass_err:
                errors['new_password'] = pass_err

        # 3. Совпадение нового пароля и подтверждения
        if new_pass != confirm_pass:
            errors['confirm_password'] = 'Пароли не совпадают'

        # Если ошибок нет — сохраняем
        if not errors:
            current_user.password_hash = generate_password_hash(new_pass)
            db.session.commit()
            flash('Пароль успешно изменен!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Исправьте ошибки в форме.', 'danger')

    return render_template('change_password.html', errors=errors, form_data=request.form)


# Функция для первоначальной настройки БД
def setup_database():
    with app.app_context():
        db.create_all()
        # Создаем роли, если их нет
        if not Role.query.first():
            r1 = Role(name='Администратор', description='Полный доступ')
            r2 = Role(name='Пользователь', description='Ограниченный доступ')
            db.session.add_all([r1, r2])
            db.session.commit()

            # Создаем админа по умолчанию
            admin = User(
                login='admin',
                password_hash=generate_password_hash('Admin123'),
                last_name='Администраторов',
                first_name='Админ',
                role_id=r1.id
            )
            db.session.add(admin)
            db.session.commit()
            print("БД создана. Логин: admin, Пароль: Admin123")


if __name__ == '__main__':
    setup_database()
    app.run(debug=True)