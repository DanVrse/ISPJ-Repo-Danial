from werkzeug.security import generate_password_hash, check_password_hash


class OrgUser:
    def __init__(self, email, username, password, phone_number, verified):
        self.__email = email
        self.__username = username
        self.__password = generate_password_hash(password)
        self.__ph_num = phone_number
        self.__role = None
        self.__verified = verified

    def get_email(self):
        return self.__email

    def get_username(self):
        return self.__username

    def get_password(self):
        return self.__password

    def get_ph_num(self):
        return self.__ph_num

    def get_role(self):
        return self.__role

    def get_verified(self):
        return self.__verified

    def set_ph_num(self, phone_number):
        self.__ph_num = phone_number

    def set_role(self, role):
        self.__role = role

    def set_permission(self, permissions):
        self.__permissions = permissions


class LogUser:
    def __init__(self, email, password):
        self.__email = email
        self.__password = generate_password_hash(password)