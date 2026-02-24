import io
import csv
from flask import Blueprint, render_template, request, Response, abort
from flask_login import login_required, current_user
from sqlalchemy import func
from models import db, Visit, User

# Создаем Blueprint для модуля логов
logs_bp = Blueprint('logs', __name__, template_folder='templates')


@logs_bp.route('/')
@login_required # Не допустит неавторизованных к защищенным страницам
def index():
    """
    Главная страница журнала посещений.
    Отображает таблицу с пагинацией.
    """
    page = request.args.get('page', 1, type=int)

    # Формируем запрос
    query = Visit.query.order_by(Visit.created_at.desc())

    # Если пользователь не админ, он видит только свои посещения
    if not current_user.is_admin:
        query = query.filter_by(user_id=current_user.id)

    # Пагинация: 10 записей на страницу
    pagination = query.paginate(page=page, per_page=10)

    return render_template('logs/index.html', pagination=pagination)


@logs_bp.route('/stats/pages')
@login_required
def stats_pages():
    """
    Статистика посещений по страницам.
    Доступна только администраторам.
    """
    if not current_user.is_admin:
        abort(403)  # Ошибка "Доступ запрещен"

    # SQL: SELECT path, count(*) FROM visit_logs GROUP BY path ORDER BY count DESC
    stats = db.session.query(Visit.path, func.count(Visit.id).label('count')) \
        .group_by(Visit.path) \
        .order_by(func.count(Visit.id).desc()).all()

    return render_template('logs/stats_pages.html', stats=stats)


@logs_bp.route('/stats/users')
@login_required
def stats_users():
    """
    Статистика посещений по пользователям.
    Доступна только администраторам.
    """
    if not current_user.is_admin:
        abort(403)

    # SQL: SELECT user_id, count(*) FROM visit_logs GROUP BY user_id ORDER BY count DESC
    stats = db.session.query(Visit.user_id, func.count(Visit.id).label('count'), User) \
        .outerjoin(User, Visit.user_id == User.id) \
        .group_by(Visit.user_id, User.id) \
        .order_by(func.count(Visit.id).desc()).all()

    return render_template('logs/stats_users.html', stats=stats)


@logs_bp.route('/export/csv/<type>')
@login_required
def export_csv(type):
    """
    Экспорт отчетов в CSV.
    type: 'pages' или 'users'
    """
    if not current_user.is_admin:
        abort(403)

    # Создаем объект в памяти для записи CSV
    output = io.StringIO()
    writer = csv.writer(output)

    if type == 'pages':
        # Заголовки
        writer.writerow(['№', 'Страница', 'Количество посещений'])
        stats = db.session.query(Visit.path, func.count(Visit.id)) \
            .group_by(Visit.path) \
            .order_by(func.count(Visit.id).desc()).all()

        for i, row in enumerate(stats, 1):
            writer.writerow([i, row[0], row[1]])

        filename = 'pages_stat.csv'

    elif type == 'users':
        writer.writerow(['№', 'Пользователь', 'Количество посещений'])
        stats = db.session.query(Visit.user_id, func.count(Visit.id), User) \
            .outerjoin(User, Visit.user_id == User.id) \
            .group_by(Visit.user_id, User.id) \
            .order_by(func.count(Visit.id).desc()).all()

        for i, row in enumerate(stats, 1):
            user_name = row[2].full_name if row[2] else "Неаутентифицированный пользователь"
            writer.writerow([i, user_name, row[1]])

        filename = 'users_stat.csv'
    else:
        abort(404)

    # Формируем ответ, который браузер поймет как скачиваемый файл
    output.seek(0)
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )