''' a variety functions for checking the password strength '''

import getpass
import re


class Constants:

    date_regex = re.compile(r'^(?:(?:31(\/|-|\.)(?:0?[13578]|1[02]))\1|(?:(?:29|30)(\/|-|\.)'
                            r'(?:0?[1,3-9]|1[0-2])\2))(?:(?:1[6-9]|[2-9]\d)?\d{2})$|^(?:29(\/|-|\.)'
                            r'0?2\3(?:(?:(?:1[6-9]|[2-9]\d)?(?:0[48]|[2468][048]|[13579][26])|'
                            r'(?:(?:16|[2468][048]|[3579][26])00))))$|^(?:0?[1-9]|1\d|2[0-8])(\/|-|\.)'
                            r'(?:(?:0?[1-9])|(?:1[0-2]))\4(?:(?:1[6-9]|[2-9]\d)?\d{2})$')

    license_regex = re.compile(r'[а-я]\d{3}[а-я]{2}\d{2,3}')
    email_regex = re.compile(r'^.+\@(\[?)[a-zA-Z0-9\-\.]+\.([a-zA-Z]{2,3}|[0-9]{1,3})(\]?)$')
    cell_regex = re.compile(r'(\d{3}[-\.\s]??\d{3}[-\.\s]??\d{4}|\(\d{3}\)\s*\d{3}[-\.\s]??\d{4}|\d{3}[-\.\s]??\d{4})')


def check_initial_strength(pwd):

    ''' return initial password strength based on it's length '''

    if len(pwd) < 5:
        initial_strength = 1
    elif len(pwd) <= 8:
        initial_strength = 2
    else:
        initial_strength = 3

    return initial_strength


def pwd_case_check(pwd):
    
    ''' check password for case-sensitivity '''
    
    return 1 if pwd != pwd.lower() and pwd != pwd.upper() else 0


def pwd_numerical_check(pwd):

    ''' check password for numbers '''

    numbers = re.findall(r'\d+', pwd)
    letters = re.findall(r'[A-Za-z]', pwd)
    return 1 if len(numbers) > 0 and len(letters) > 0 else 0


def pwd_spchar_check(pwd):

    ''' check password for special characters '''

    special_char = re.findall(r'[^A-Za-z0-9]', pwd)
    return 1 if len(special_char) > 0 else 0


def pwd_blacklist_check(pwd):

    ''' check if password is within blacklist '''

    while True:
        try:
            blacklist_path = input('Enter the path to your password blacklist: ')
            with open(blacklist_path) as blacklist:
                blacklist = blacklist.read().splitlines()
            return True if pwd not in blacklist else False

        except FileNotFoundError:
            print('No such file found, try again...')


def pwd_check_formats(regex, pwd):

    '''
    Check password against different regex-expressions

    :param format: compiled regex expression
    :param pwd: password for checking against regex expression
    :return: 1 if True, 0 if False (useful for adding up in case of multiple checks)
    '''

    result = re.search(regex, pwd)

    return 1 if not result else 0


def count_password_strength(common_checklist, personal_checklist):

    '''
    Count password strength based on two function tuples

    :param common_checklist: tuple with general functions that check the password
    :param personal_checklist: tuple with personal info functions that check the password
    :return: sum of the common checks (maximum is 7), plus 3 if all personal checks are True
    '''

    PERSONAL_MAXIMUM = 3

    if sum(personal_checklist) == len(personal_checklist):
        return sum(common_checklist) + PERSONAL_MAXIMUM
    else:
        return sum(common_checklist)


def print_password(password_strength):

    ''' Pretty print the password strength :param password_strength: a number from 0 to 10 '''

    strength_string = '█' * password_strength
    empty_strength = '░' * (10 - password_strength)

    print('Your passwords strength:', password_strength , '/ 10', sep=' ')
    print(strength_string + empty_strength)


def main():

    ''' Return the password strength based on a variety of common and personal info checks '''

    pwd = getpass.getpass('Enter your password: ')

    common_checklist = (
        check_initial_strength(pwd),
        pwd_case_check(pwd),
        pwd_numerical_check(pwd),
        pwd_spchar_check(pwd),
        pwd_blacklist_check(pwd),
        )

    personal_checklist = (
        pwd_check_formats(Constants.date_regex, pwd),
        pwd_check_formats(Constants.license_regex, pwd),
        pwd_check_formats(Constants.email_regex, pwd),
        pwd_check_formats(Constants.cell_regex, pwd)
        )

    password_strength = count_password_strength(common_checklist, personal_checklist)
    print_password(password_strength)

if __name__ == '__main__':
    main()
