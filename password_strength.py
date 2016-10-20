import re


def run_password_checks(pwd, blacklist):

    def check_initial_strength():
        if len(pwd) < 5:
            initial_strength = 1
        elif len(pwd) <= 8:
            initial_strength = 2
        else:
            initial_strength = 3

        return initial_strength

    def pwd_case_check():
        if pwd != pwd.lower() and pwd != pwd.upper():
            return True
        else:
            return False

    def pwd_numerical_check():
        numbers = re.findall(r'\d+', pwd)
        letters = re.findall(r'[A-Za-z]', pwd)

        if len(numbers) > 0 and len(letters) > 0:
            return True
        else:
            return False

    def pwd_spchar_check():
        special_char = re.findall(r'[^A-Za-z0-9]', pwd)

        if len(special_char) > 0:
            return True
        else:
            return False

    def pwd_blacklist_check(blacklist):
        with open(blacklist) as blacklist:
            blacklist = blacklist.read().splitlines()

        if pwd not in blacklist:
            return True
        else:
            return False

    checklist = [check_initial_strength(),
                 pwd_case_check(),
                 pwd_numerical_check(),
                 pwd_spchar_check(),
                 pwd_blacklist_check(blacklist)]

    strength = sum(checklist)

    def personal_info_check():

        date_check = re.compile(r'^(?:(?:31(\/|-|\.)(?:0?[13578]|1[02]))\1|(?:(?:29|30)(\/|-|\.)(?:0?[1,3-9]|1[0-2])\2))(?:(?:1[6-9]|[2-9]\d)?\d{2})$|^(?:29(\/|-|\.)0?2\3(?:(?:(?:1[6-9]|[2-9]\d)?(?:0[48]|[2468][048]|[13579][26])|(?:(?:16|[2468][048]|[3579][26])00))))$|^(?:0?[1-9]|1\d|2[0-8])(\/|-|\.)(?:(?:0?[1-9])|(?:1[0-2]))\4(?:(?:1[6-9]|[2-9]\d)?\d{2})$')
        license_check = re.compile(r'[а-я]\d{3}[а-я]{2}\d{2,3}')
        email_check = re.compile(r'^.+\@(\[?)[a-zA-Z0-9\-\.]+\.([a-zA-Z]{2,3}|[0-9]{1,3})(\]?)$')
        cell_phone = re.compile(r'(\d{3}[-\.\s]??\d{3}[-\.\s]??\d{4}|\(\d{3}\)\s*\d{3}[-\.\s]??\d{4}|\d{3}[-\.\s]??\d{4})')

        def pwd_check_formats(format):
            result = re.search(format, pwd)
            if result is not None:
                return True
            else:
                return False

        format_checklist = [pwd_check_formats(date_check),
                            pwd_check_formats(license_check),
                            pwd_check_formats(email_check),
                            pwd_check_formats(cell_phone)]

        if sum(format_checklist) == 0:
            # Пароль надёжный, проверка пройдена
            return True
        else:
            return False

    if personal_info_check():
        strength += 3

    return strength

if __name__ == '__main__':

    pwd = input('Введите пароль для оценки его сложности: ')
    blacklist = input('Введите текстовый файл с чёрным списком паролей: ')

    # Результат
    
    print('Сложность вашего пароля: ', run_password_checks(pwd, blacklist), '/ 10')

    # Красивый вывод
    
    strength_string = '█' * run_password_checks(pwd, blacklist)
    empty_strength = '░' * (10 - run_password_checks(pwd, blacklist))

    print(strength_string + empty_strength)
