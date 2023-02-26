import glob
import pickle, os
from werkzeug.security import generate_password_hash, check_password_hash


# class User:
#     def __init__(self, email, password):
#         self.__email = email
#         self.__password = password
#
#     def get_email(self):
#         # print(type(self.__email))
#         return self.__email
#
#     def get_password(self):
#         return self.__password
#
#
# user = User('danial@gmail.com', generate_password_hash('password'))
# data = [user.get_email(), user.get_password()]
#
# a = pickle.dumps(data)
# print(type(a), a)
#
# b = pickle.loads(a)
# print(type(b), b)

path_locate = dir_path = os.path.dirname(os.path.abspath(__file__))

text_files = glob.glob(path_locate + "/**/*.db", recursive=True)

print('Searching in {}'.format(path_locate))
print(text_files)