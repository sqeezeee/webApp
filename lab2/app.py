from flask import Flask, render_template, request, make_response

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


# Задание 1: Отображение данных запроса и форма авторизации

@app.route('/request-info', methods=['GET', 'POST'])
def request_info():
    url_params = request.args
    headers = request.headers
    cookies = request.cookies

    form_params = request.form

    # Рендерим шаблон и передаем туда все данные
    resp = make_response(render_template('request_info.html',
                                         url_params=url_params,
                                         headers=headers,
                                         cookies=cookies,
                                         form_params=form_params))

    # Установим куку для демонстрации, если её нет
    if 'test_cookie' not in cookies:
        resp.set_cookie('test_cookie', 'Hello, world!')

    return resp


# ЗАДАНИЕ 2: Форма с обработкой ошибок (номер телефона)

@app.route('/phone', methods=['GET', 'POST'])
def phone_check():
    if request.method == 'GET':
        return render_template('phone_form.html', error=None, phone_value='')

    # Получаем введенное значение
    raw_phone = request.form.get('phone', '').strip()

    # Логика валидации

    # 1. Проверка на недопустимые символы
    allowed_chars = set('0123456789 ()-.+')
    if not set(raw_phone).issubset(allowed_chars):
        error_msg = "Недопустимый ввод. В номере телефона встречаются недопустимые символы."
        return render_template('phone_form.html', error=error_msg, phone_value=raw_phone)

    # 2. Подсчет цифр
    digits = [char for char in raw_phone if char.isdigit()]
    digits_count = len(digits)

    # 3. Логика длины (10 или 11 цифр в зависимости от префикса)

    is_valid_length = False

    if raw_phone.startswith('+7') or raw_phone.startswith('8'):
        if digits_count == 11:
            is_valid_length = True
    else:
        if digits_count == 10:
            is_valid_length = True

    if not is_valid_length:
        error_msg = "Недопустимый ввод. Неверное количество цифр."
        return render_template('phone_form.html', error=error_msg, phone_value=raw_phone)

    # Преобразовываем к формату 8-***-***-**-**

    clean_digits = "".join(digits)
    if len(clean_digits) == 11:
        main_part = clean_digits[1:]  # отбрасываем первую 7 или 8
    else:
        main_part = clean_digits  # это и есть 10 цифр

    # Формируем строку: 8-***-***-**-**
    formatted_phone = f"8-{main_part[0:3]}-{main_part[3:6]}-{main_part[6:8]}-{main_part[8:10]}"

    return render_template('phone_form.html', success=formatted_phone, phone_value=raw_phone)


if __name__ == '__main__':
    app.run(debug=True)