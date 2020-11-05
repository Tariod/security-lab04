from argon2 import PasswordHasher
from argon2.low_level import Type
import hashlib
from numpy.random import default_rng
import string
import secrets

ALPHABET = string.ascii_letters + string.digits + string.punctuation
BATCH_SIZE = 100000
OUTPUT_FILE_NAME = 'output'


def common_password_generator(list_path):
    common_password_list = []
    with open(list_path) as file:
        common_password_list = file.read().split('\n')
        common_password_list.pop()

    def generate():
        return secrets.choice(common_password_list)

    return generate


def top_100():
    generator = common_password_generator('common-passwords/10-million-password-list-top-100.txt')
    return generator


def top_1000000():
    generator = common_password_generator('common-passwords/10-million-password-list-top-1000000.txt')
    return generator


def random_password_generator():
    def generate():
        password = ''
        while len(password) < 8:
            length = secrets.randbelow(32)
            password = ''.join(secrets.choice(ALPHABET) for _ in range(length))
        return password

    return generate


def lowercase(password):
    return password.lower()


def uppercase(password):
    return password.upper()


def capitalize(password):
    return password.capitalize()


def invert_capitalize(password):
    return password[:1].lower() + password[1:]


def toggle_case(password):
    return password.swapcase()


def toggle_character(password):
    character = secrets.randbelow(len(password))
    return ''.join(password[c].swapcase() if c == character else password[c] for c in range(len(password)))


def reverse_password(password):
    return password[::-1]


def duplicate(password):
    return password + password


def reflect(password):
    return password + reverse_password(password)


def rotate_left(password):
    return password[1:] + password[:1]


def rotate_right(password):
    return password[-1:] + password[:-1]


def append_character(password):
    return password + secrets.choice(ALPHABET)


def prepend_character(password):
    return secrets.choice(ALPHABET) + password


def replace(password):
    return password.replace(secrets.choice(password), secrets.choice(ALPHABET))


def duplicate_all(password):
    return ''.join(c + c for c in password)


def john_the_ripper_like_generator(default_generator):
    rng = default_rng()
    rule_engine = [
        lowercase, uppercase, capitalize,
        invert_capitalize, toggle_case, toggle_character,
        reverse_password, duplicate, reflect,
        rotate_left, rotate_right, append_character,
        prepend_character, replace, duplicate_all
    ]

    def generate():
        probability, probability_delta = 1, 0.3
        password = ''
        while len(password) == 0 and probability > 0:
            if rng.random() < probability:
                password += default_generator()
            probability -= probability_delta

        probability, probability_delta = 1, 0.2
        while probability > 0:
            if rng.random() < probability:
                rule = rng.choice(rule_engine)
                password = rule(password)
            probability -= probability_delta

        return password

    return generate


def generate_password(batch_size):
    top_100_generator = top_100()
    top_1000000_generator = top_1000000()
    random_generator = random_password_generator()
    ripper_generator = john_the_ripper_like_generator(top_1000000_generator)

    # 5:80:5:10
    coef = batch_size // 20

    passwords = []
    for _ in range(coef * 1):
        passwords.append(top_100_generator())
    for _ in range(coef * 16):
        passwords.append(top_1000000_generator())

    for _ in range(coef * 1):
        passwords.append(random_generator())

    for _ in range(coef * 2):
        passwords.append(ripper_generator())

    rng = default_rng()
    rng.shuffle(passwords)

    return passwords


if __name__ == '__main__':
    # sha1
    input_passwords = generate_password(BATCH_SIZE)
    print('SHA1: Passwords generated')

    hashes = [hashlib.sha1(bytes(p, 'utf-8')).hexdigest() for p in input_passwords]
    print('SHA1: Passwords hashed')

    with open(OUTPUT_FILE_NAME + '_sha1.csv', 'w') as f:
        for h in hashes:
            f.write(h + '\n')
    print('SHA1: Finished')

    # sha1 + salt
    input_passwords = generate_password(BATCH_SIZE)
    print('SHA1 + SALT: Passwords generated')

    hashes = []
    for p in input_passwords:
        salt = secrets.token_hex(16)
        hashes.append([hashlib.sha1(bytes(p + salt, 'utf-8')).hexdigest(), salt])
    print('SHA1 + SALT: Passwords hashed')

    with open(OUTPUT_FILE_NAME + '_sha1_salt.csv', 'w') as f:
        for h in hashes:
            f.write(h[0] + ',' + h[1] + '\n')
    print('SHA1 + SALT: Finished')

    # argon2i
    input_passwords = generate_password(BATCH_SIZE)
    print('ARGON2I: Passwords generated')

    ph = PasswordHasher(memory_cost=25600, type=Type.I)
    hashes = []
    for i, p in enumerate(input_passwords):
        if i % (BATCH_SIZE / 100) == 0:
            print('ARGON2I: Password hashing progress ' + str(i) + '/' + str(BATCH_SIZE))
        salt, h = ph.hash(p).split('$')[-2:]
        hashes.append([h, salt])
    print('ARGON2I: Passwords hashed')

    with open(OUTPUT_FILE_NAME + '_argon2i.csv', 'w') as f:
        for h in hashes:
            f.write(h[0] + ',' + h[1] + '\n')
    print('ARGON2I: Finished')
