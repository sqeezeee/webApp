from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()


class Role(db.Model):
    """Модель роли пользователя."""
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=True)
    users = db.relationship('User', backref='role', lazy=True)

    def __repr__(self):
        return f'<Role {self.name}>'


class User(db.Model, UserMixin):
    """Модель учетной записи пользователя."""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    middle_name = db.Column(db.String(50), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def full_name(self):
        parts = [self.last_name, self.first_name, self.middle_name]
        return ' '.join(p for p in parts if p)

    @property
    def is_admin(self):
        """
        Проверяет, является ли пользователь администратором (роль администратора имеет id=1, как создано в setup_database app.py).
        """
        return self.role_id == 1

    def __repr__(self):
        return f'<User {self.login}>'


class Visit(db.Model):
    """
    Модель для журнала посещений.
    """
    __tablename__ = 'visit_logs'
    # ID записи
    id = db.Column(db.Integer, primary_key=True)
    # Путь страницы
    path = db.Column(db.String(100), nullable=False)
    # ID пользователя (может быть NULL, если пользователь не вошел)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    # Дата посещения
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Связь с пользователем для удобного отображения ФИО
    user = db.relationship('User', backref='visits', lazy=True)

    def __repr__(self):
        return f'<Visit {self.path} by {self.user_id}>'