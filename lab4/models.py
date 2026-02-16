from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


class Role(db.Model):
    """
    Модель роли пользователя.
    """
    __tablename__ = 'roles'

    # Уникальный идентификатор записи
    id = db.Column(db.Integer, primary_key=True)
    # Название роли (обязательно)
    name = db.Column(db.String(50), nullable=False)
    # Описание (может быть пустым)
    description = db.Column(db.Text, nullable=True)

    # Связь с пользователями
    users = db.relationship('User', backref='role', lazy=True)

    def __repr__(self):
        return f'<Role {self.name}>'


class User(db.Model, UserMixin):
    """
    Модель учетной записи пользователя.
    """
    __tablename__ = 'users'

    # Уникальный идентификатор записи
    id = db.Column(db.Integer, primary_key=True)

    # Логин уникален и обязателен
    login = db.Column(db.String(50), unique=True, nullable=False)

    # Хеш пароля (храним строку)
    password_hash = db.Column(db.String(128), nullable=False)

    # Фамилия - обязательно
    last_name = db.Column(db.String(50), nullable=False)

    # Имя - обязательно
    first_name = db.Column(db.String(50), nullable=False)

    # Отчество - может отсутствовать
    middle_name = db.Column(db.String(50), nullable=True)

    # Роль - может отсутствовать
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=True)

    # Дата создания - проставляется автоматически
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def full_name(self):
        """
        Возвращает полное имя, пропуская пустые поля.
        """
        parts = [self.last_name, self.first_name, self.middle_name]
        # Соединяем только те части, которые не None и не пустые строки
        return ' '.join(p for p in parts if p)