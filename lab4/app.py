import re
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Role, Visit
from logs import logs_bp

app = Flask(__name__)

# Конфигурация
app.config['SECRET_KEY'] = 'secret_key_lab5_rbac'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализация
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Регистрируем Blueprint с журналами
app.register_blueprint(logs_bp, url_prefix='/logs')

login_manager.login_view = 'login'
login_manager.login_message = "Пожалуйста, войдите для доступа к этой странице."
login_manager.login_message_category = "warning"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Логирование посещений

@app.before_request
def log_request_info():
    """
    Декоратор, срабатывающий перед каждым запросом.
    Записывает информацию о посещении в БД.
    """
    # Игнорируем запросы к статическим файлам (картинки, css), чтобы не засорять бд
    if request.path.startswith('/static'):
        return

    # Определяем user_id (если вошел - id, если нет - None)
    user_id = current_user.id if current_user.is_authenticated else None

    # Создаем и сохраняем запись
    visit = Visit(path=request.path, user_id=user_id)
    db.session.add(visit)
    db.session.commit()


# Проверка прав

def check_rights(action):
    """
    Декоратор для проверки прав доступа.
    action: строка, описывающая действие ('create', 'edit', 'delete', 'show').
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Если пользователь не вошел - отправляем на страницу авторизации
            if not current_user.is_authenticated:
                return redirect(url_for('login'))

            has_rights = False

            # Логика прав

            # У администратора все права
            if current_user.is_admin:
                has_rights = True

            # Логика для обычного Пользователя
            else:
                if action == 'show':
                    # Просмотр: можно смотреть только свой профиль
                    # user_id берется из URL-параметров (kwargs)
                    record_id = kwargs.get('user_id')
                    if record_id == current_user.id:
                        has_rights = True

                elif action == 'edit':
                    # Редактирование: можно менять только свои данные
                    record_id = kwargs.get('user_id')
                    if record_id == current_user.id:
                        has_rights = True

                # 'create', 'delete' - для обычного юзера запрещены (has_rights останется False)

            if not has_rights:
                flash("У вас недостаточно прав для доступа к данной странице.", "danger")
                return redirect(url_for('index'))

            return func(*args, **kwargs)

        return wrapper

    return decorator


# context processor позволяет использовать функцию can_user_perform в любом шаблоне HTML для скрытия/показа кнопок.
@app.context_processor
def inject_permissions():
    def can_user_perform(action, record=None):
        if not current_user.is_authenticated:
            return False
        if current_user.is_admin:
            return True

        # Права обычного пользователя
        if action == 'edit' or action == 'show':
            # Если передана запись (пользователь) и их ID совпадают
            return record and record.id == current_user.id

        # 'create', 'delete' запрещены
        return False

    return dict(can_user_perform=can_user_perform)


# Функции валидации
def validate_user_input(form_data, is_edit=False):
    errors = {}
    if not form_data.get('last_name'): errors['last_name'] = 'Поле не может быть пустым'
    if not form_data.get('first_name'): errors['first_name'] = 'Поле не может быть пустым'
    if not is_edit:
        login = form_data.get('login', '')
        if not login:
            errors['login'] = 'Поле не может быть пустым'
        elif len(login) < 5:
            errors['login'] = 'Логин должен быть не менее 5 символов'
        elif not re.match(r'^[a-zA-Z0-9]+$', login):
            errors['login'] = 'Только латинские буквы и цифры'
        elif User.query.filter_by(login=login).first():
            errors['login'] = 'Такой логин уже занят'
        password = form_data.get('password', '')
        pass_error = check_password_requirements(password)
        if pass_error: errors['password'] = pass_error
    return errors


def check_password_requirements(password):
    if not password: return 'Поле не может быть пустым'
    if not (8 <= len(password) <= 128): return 'Длина 8-128 символов'
    if ' ' in password: return 'Без пробелов'
    if not re.match(r'^[a-zA-Zа-яА-Я0-9~!@#$%^&*_\-+()\[\]{}><\/\\|"\'. ,:;]+$',
                    password): return 'Недопустимые символы'
    if not (any(c.isupper() for c in password) and any(c.islower() for c in password) and any(
        c.isdigit() for c in password)): return 'Нужна заглавная, строчная и цифра'
    return None


# Маршруты

@app.route('/')
def index():
    users = User.query.order_by(User.id).all()
    return render_template('index.html', users=users)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        user = User.query.filter_by(login=request.form.get('login')).first()
        if user and check_password_hash(user.password_hash, request.form.get('password')):
            login_user(user, remember=bool(request.form.get('remember')))
            flash('Вы успешно вошли!', 'success')
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


@app.route('/users/<int:user_id>')
@login_required
@check_rights('show')  # Проверка прав на просмотр
def user_view(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('user_view.html', user=user)


@app.route('/users/create', methods=['GET', 'POST'])
@login_required
@check_rights('create')  # Только админ
def user_create():
    roles = Role.query.all()
    if request.method == 'POST':
        errors = validate_user_input(request.form, is_edit=False)
        if errors:
            flash('Ошибка валидации.', 'danger')
            return render_template('user_form.html', roles=roles, form_data=request.form, errors=errors, is_edit=False)
        try:
            # Превращаем пустой role_id в None
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
            flash('Пользователь создан!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка БД: {e}', 'danger')
    return render_template('user_form.html', roles=roles, form_data={}, errors={}, is_edit=False)


@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@check_rights('edit')  # Админ или сам пользователь
def user_edit(user_id):
    user = User.query.get_or_404(user_id)
    roles = Role.query.all()

    if request.method == 'POST':
        errors = validate_user_input(request.form, is_edit=True)
        if errors:
            flash('Ошибка валидации.', 'danger')
            return render_template('user_form.html', roles=roles, form_data=request.form, errors=errors, is_edit=True,
                                   user=user)
        try:
            user.last_name = request.form['last_name']
            user.first_name = request.form['first_name']
            user.middle_name = request.form['middle_name']

            # Менять роль может только администратор
            if current_user.is_admin:
                role_id = request.form.get('role_id')
                user.role_id = int(role_id) if role_id else None

            db.session.commit()
            flash('Пользователь обновлен.', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка: {e}', 'danger')

    form_data = {
        'last_name': user.last_name,
        'first_name': user.first_name,
        'middle_name': user.middle_name,
        'role_id': user.role_id
    }
    return render_template('user_form.html', roles=roles, form_data=form_data, errors={}, is_edit=True, user=user)


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@check_rights('delete')  # Только админ
def user_delete(user_id):
    user = User.query.get_or_404(user_id)
    try:
        db.session.delete(user)
        db.session.commit()
        flash(f'Пользователь {user.full_name} удален.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Ошибка при удалении.', 'danger')
    return redirect(url_for('index'))


@app.route('/account/password', methods=['GET', 'POST'])
@login_required
def change_password():
    # Логика смены пароля
    errors = {}
    if request.method == 'POST':
        old_pass = request.form.get('old_password')
        new_pass = request.form.get('new_password')
        confirm_pass = request.form.get('confirm_password')
        if not check_password_hash(current_user.password_hash, old_pass):
            errors['old_password'] = 'Неверный старый пароль'
        elif old_pass == new_pass:
            errors['new_password'] = 'Пароли совпадают'
        if 'new_password' not in errors:
            pass_err = check_password_requirements(new_pass)
            if pass_err: errors['new_password'] = pass_err
        if new_pass != confirm_pass: errors['confirm_password'] = 'Пароли не совпадают'
        if not errors:
            current_user.password_hash = generate_password_hash(new_pass)
            db.session.commit()
            flash('Пароль изменен!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Исправьте ошибки.', 'danger')
    return render_template('change_password.html', errors=errors, form_data=request.form)


def setup_database():
    with app.app_context():
        db.create_all()
        if not Role.query.first():
            # ID=1 - Администратор
            r1 = Role(name='Администратор', description='Полный доступ')
            # ID=2 - Пользователь
            r2 = Role(name='Пользователь', description='Ограниченный доступ')
            db.session.add_all([r1, r2])
            db.session.commit()

            admin = User(login='admin', password_hash=generate_password_hash('Admin123'),
                         last_name='Админов', first_name='Петр', role_id=r1.id)
            user = User(login='user', password_hash=generate_password_hash('User1234'),
                        last_name='Юзеров', first_name='Иван', role_id=r2.id)
            db.session.add_all([admin, user])
            db.session.commit()
            print("БД создана.")


if __name__ == '__main__':
    setup_database()
    app.run(debug=True)