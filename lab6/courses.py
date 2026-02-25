from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from sqlalchemy.exc import IntegrityError
from sqlalchemy import desc, asc
from models import db, Course, Category, User, Review
from tools import CoursesFilter, ImageSaver

bp = Blueprint('courses', __name__, url_prefix='/courses')

COURSE_PARAMS = [
    'author_id', 'name', 'category_id', 'short_desc', 'full_desc'
]

def params():
    return {p: request.form.get(p) or None for p in COURSE_PARAMS}

def search_params():
    return {
        'name': request.args.get('name'),
        'category_ids': [x for x in request.args.getlist('category_ids') if x],
    }

@bp.route('/')
def index():
    courses = CoursesFilter(**search_params()).perform()
    pagination = db.paginate(courses)
    courses = pagination.items
    categories = db.session.execute(db.select(Category)).scalars()
    return render_template('courses/index.html',
                           courses=courses,
                           categories=categories,
                           pagination=pagination,
                           search_params=search_params())

@bp.route('/new')
@login_required
def new():
    course = Course()
    categories = db.session.execute(db.select(Category)).scalars()
    users = db.session.execute(db.select(User)).scalars()
    return render_template('courses/new.html',
                           categories=categories,
                           users=users,
                           course=course)

@bp.route('/create', methods=['POST'])
@login_required
def create():
    f = request.files.get('background_img')
    img = None
    course = Course()
    try:
        if f and f.filename:
            img = ImageSaver(f).save()

        image_id = img.id if img else None
        course = Course(**params(), background_image_id=image_id)
        db.session.add(course)
        db.session.commit()
    except IntegrityError as err:
        flash(f'Возникла ошибка при записи данных в БД. Проверьте корректность введённых данных. ({err})', 'danger')
        db.session.rollback()
        categories = db.session.execute(db.select(Category)).scalars()
        users = db.session.execute(db.select(User)).scalars()
        return render_template('courses/new.html',
                               categories=categories,
                               users=users,
                               course=course)

    flash(f'Курс {course.name} был успешно добавлен!', 'success')

    return redirect(url_for('courses.index'))

# Страница просмотра всех отзывов о курсе
@bp.route('/<int:course_id>')
def show(course_id):
    # Получаем курс или ошибку
    course = db.get_or_404(Course, course_id)

    # Получаем 5 последних отзывов для отображения на главной странице курса
    # Сортируем по дате создания
    recent_reviews = db.session.execute(
        db.select(Review).filter_by(course_id=course_id).order_by(desc(Review.created_at)).limit(5)
    ).scalars().all()

    # Проверяем, оставлял ли текущий пользователь отзыв к этому курсу
    user_review = None
    if current_user.is_authenticated:
        user_review = db.session.execute(
            db.select(Review).filter_by(course_id=course_id, user_id=current_user.id)
        ).scalar()

    return render_template('courses/show.html',
                           course=course,
                           recent_reviews=recent_reviews,
                           user_review=user_review)


# Маршрут для сохранения нового отзыва
@bp.route('/<int:course_id>/reviews/add', methods=['POST'])
@login_required
def add_review(course_id):
    course = db.get_or_404(Course, course_id)

    # Проверка: пользователь не может оставить второй отзыв
    existing_review = db.session.execute(
        db.select(Review).filter_by(course_id=course_id, user_id=current_user.id)
    ).scalar()

    if existing_review:
        flash('Вы уже оставили отзыв к этому курсу.', 'warning')
        return redirect(url_for('courses.show', course_id=course_id))

    # Получаем данные из формы
    rating = request.form.get('rating')
    text = request.form.get('text')

    # Валидация на наличие данных
    if not rating or not text:
        flash('Заполните все поля отзыва.', 'danger')
        return redirect(url_for('courses.show', course_id=course_id))

    try:
        rating = int(rating)
        # Создаем объект отзыва
        review = Review(
            rating=rating,
            text=text,
            course_id=course_id,
            user_id=current_user.id
        )
        db.session.add(review)

        # Пересчитываем рейтинг курса
        course.rating_num += 1
        course.rating_sum += rating

        db.session.commit()
        flash('Отзыв успешно добавлен!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при сохранении отзыва: {e}', 'danger')

    return redirect(url_for('courses.show', course_id=course_id))


# Маршрут для просмотра всех отзывов с пагинацией и сортировкой
@bp.route('/<int:course_id>/reviews')
def reviews(course_id):
    course = db.get_or_404(Course, course_id)

    # Получаем параметр сортировки из URL
    sort_by = request.args.get('sort_by', 'new')

    # Формируем запрос
    query = db.select(Review).filter_by(course_id=course_id)

    # Применяем сортировку в зависимости от выбора
    if sort_by == 'positive':
        # Сначала положительный рейтинг, затем по новизне
        query = query.order_by(desc(Review.rating), desc(Review.created_at))
    elif sort_by == 'negative':
        # Сначала отрицательный рейтинг, затем по новизне
        query = query.order_by(asc(Review.rating), desc(Review.created_at))
    else:
        # По новизне (по умолчанию)
        query = query.order_by(desc(Review.created_at))

    # Пагинация
    pagination = db.paginate(query, per_page=5)  # 5 отзывов на страницу
    reviews = pagination.items

    # Проверяем, оставлял ли текущий пользователь отзыв к этому курсу
    user_review = None
    if current_user.is_authenticated:
        user_review = db.session.execute(
            db.select(Review).filter_by(course_id=course_id, user_id=current_user.id)
        ).scalar()

    return render_template('courses/reviews.html',
                           course=course,
                           reviews=reviews,
                           pagination=pagination,
                           sort_by=sort_by)