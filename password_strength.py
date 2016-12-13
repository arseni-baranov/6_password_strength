import getpass
import re


def length_check(password):
    if len(password) > 8:
        return 3
    elif len(password) > 5:
        return 2
    elif len(password) == 0:
        return 0
    else:
        return 1


def case_sensitivity_check(password):
    return bool(password != password.lower() and password != password.upper())


def numbers_check(password):
    numbers = re.findall(r'\d+', password)
    letters = re.findall(r'[A-Za-z]', password)
    return bool(len(numbers) > 0 and len(letters) > 0)


def special_characters_check(password):
    special_char = re.findall(r'[^A-Za-z0-9]', password)
    return bool(len(special_char) > 0)


def load_blacklist():
    while True:
        try:
            blacklist_path = input('Enter the path to your password blacklist: ')
            with open(blacklist_path) as blacklist:
                blacklist = blacklist.read().splitlines()
                return blacklist
        except FileNotFoundError:
            print('No such file found, try again...')


def blacklist_check(password, blacklist):
    return bool(password not in blacklist)


def bad_ideas_check(password):
    date_regex = re.compile(r'^(?:(?:31(\/|-|\.)(?:0?[13578]|1[02]))\1|(?:(?:29|30)(\/|-|\.)'
                            r'(?:0?[1,3-9]|1[0-2])\2))(?:(?:1[6-9]|[2-9]\d)?\d{2})$|^(?:29(\/|-|\.)'
                            r'0?2\3(?:(?:(?:1[6-9]|[2-9]\d)?(?:0[48]|[2468][048]|[13579][26])|'
                            r'(?:(?:16|[2468][048]|[3579][26])00))))$|^(?:0?[1-9]|1\d|2[0-8])(\/|-|\.)'
                            r'(?:(?:0?[1-9])|(?:1[0-2]))\4(?:(?:1[6-9]|[2-9]\d)?\d{2})$')

    license_regex = re.compile(r'[а-я]\d{3}[а-я]{2}\d{2,3}')
    email_regex = re.compile(r'^.+\@(\[?)[a-zA-Z0-9\-\.]+\.([a-zA-Z]{2,3}|[0-9]{1,3})(\]?)$')
    cellphone_regex = re.compile(r'(\d{3}[-\.\s]??\d{3}[-\.\s]??\d{4}|\(\d{3}\)\s*\d{3}'
                                 r'[-\.\s]??\d{4}|\d{3}[-\.\s]??\d{4})')

    bad_ideas = date_regex, license_regex, email_regex, cellphone_regex

    for regex in bad_ideas:
        if not re.search(regex, password):
            return 3


def print_strength(password_strength):
    strength_string = '█' * password_strength
    empty_strength = '░' * (10 - password_strength)

    print('Your passwords strength:', password_strength , '/ 10', sep=' ')
    print(strength_string + empty_strength)


def main():
    password = getpass.getpass('Enter your password: ')
    password_strength = length_check(password)

    checklist = [case_sensitivity_check(password),
                 numbers_check(password),
                 special_characters_check(password),
                 blacklist_check(password, load_blacklist()),
                 bad_ideas_check(password)]

    if password_strength > 1:
        password_strength += sum(checklist)
        print_strength(password_strength)
    else:
        print_strength(password_strength)

if __name__ == '__main__':
    main()
