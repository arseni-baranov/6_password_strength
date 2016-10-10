import re
import os.path


def check_email(user_email):

    email_words = user_email.split('@')

    if user_email not in password:
        for word in email_words:
            if word not in password:
                return True


def check_cellphone(cellphone):

    if cellphone not in password:
        return True


def check_cellphone_format(user_cell):

    if user_cell[0:1] == '+':
        user_cell = user_cell[2:]
        return user_cell
    else:
        return user_cell


def birthday_split_check(delimiter, user_bday):
    bday_list = user_bday.split(delimiter)

    for bday in bday_list:
        if bday not in password and user_bday not in password:
            return True


def check_birthsday(user_bday):

    if '.' in user_bday:
        return birthday_split_check('.', user_bday)

    elif '/' in user_bday:
        return birthday_split_check('/', user_bday)

    elif ' ' in user_bday:
        return birthday_split_check(' ', user_bday)


def check_user_name(password, user_name):

    username_strength = 0

    for name in user_name:
        if name not in password:
            username_strength += 1

    return username_strength


def check_user_data(password):

    add_to_strength = 0

    birthsday = input('Введите вашу дату рождения: ')
    user_name = input('Введите ваше ФИО: ').split(' ')
    cellphone = check_cellphone_format(input('Введите ваш номер телефона: '))
    user_mail = input('Введите ваш email: ')
    user_job = input('Введите ваше место работы: ')
    user_license_plate = input('Введите номер вашей машины (при наличии): ')

    if check_user_name(password, user_name) is 3:
        add_to_strength += 1

    if user_job not in password:
        if user_license_plate not in password:
            if check_email(user_mail) is True:
                add_to_strength += 1

    if check_birthsday(birthsday) is True:
        if check_email(user_mail) is True:
            if check_cellphone(cellphone) is True:
                add_to_strength += 1

    return add_to_strength


def password_blacklist_check(blacklist_file):

    with open(blacklist_file) as blacklist:
        password_list = blacklist.read().splitlines()

    if password not in password_list:
        return True


def password_spec_char_check():
    special_char = re.findall(r'[^A-Za-z0-9]', password)

    if len(special_char) > 0:
        return True


def password_numbers_check():
    numbers = re.findall(r'\d+', password)
    letters = re.findall(r'[A-Za-z]', password)

    if len(numbers) > 0 and len(letters) > 0:
        return True


def password_case_check():
    pass_lower = password.lower()
    pass_upper = password.upper()

    if not (pass_lower == password or pass_upper == password):
        return True


def get_password_strength(blacklist):
    if len(password) < 5:
        pass_strength = 1
    elif len(password) <= 8:
        pass_strength = 2
    else:
        pass_strength = 3

    if password_case_check() is True:
        pass_strength += 1

    if password_numbers_check() is True:
        pass_strength += 1

    if password_spec_char_check() is True:
        pass_strength += 1

    if password_blacklist_check(blacklist) is True:
        pass_strength += 1

    return 'Сложность вашего пароля: ' + str(pass_strength + check_user_data(password)) + '/10'


if __name__ == '__main__':

    blacklist = input('Введие название текстового файла с часто используемыми паролями: ')

    current_dir = os.path.abspath(__file__)
    script_name = os.path.basename(__file__)

    blacklist_file = current_dir.replace(script_name, '') + blacklist

    password = input('Введите пароль, и мы оценим его сложность : ')
    print(get_password_strength(blacklist_file))
