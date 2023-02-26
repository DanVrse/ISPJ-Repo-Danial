import sqlite3, csv, os
from werkzeug.security import generate_password_hash, check_password_hash

# Database Creation
def db_Create(orgPath):
    print('\ndb_Create: STARTING...\n')
    conn = None
    try:
        # conn = sqlite3.connect('static/User_Folder/cred_DB.db')
        dbPath = os.path.join(orgPath, 'orgDB.db')
        conn = sqlite3.connect(dbPath)
        c = conn.cursor()

        c.execute('CREATE TABLE IF NOT EXISTS userList'
                  '([email] TEXT PRIMARY KEY, [username] TEXT NOT NULL UNIQUE, '
                  '[password] TEXT NOT NULL, [role] TEXT, [phone_number] TEXT NOT NULL, [verified] TEXT NOT NULL);')

        print('\nNew TABLE created!\n')

    except sqlite3.Error as error:
        print("Error while connecting to sqlite", error)

    finally:
        if conn:
            print("Total Rows affected since the database connection was opened: ", conn.total_changes)
            conn.commit()
            conn.close()
            print('\ndb_Create: FINISHED.\nThe connection has been closed.\n')
            return


# Register the user into the database.
def db_Register(userObj, orgPath):
    print('\ndb_Register: STARTING...\n')
    conn = None
    existEmail = False

    # Before appending database, it checks if email already exists.
    try:
        dbPath = os.path.join(orgPath, 'orgDB.db')
        conn = sqlite3.connect(dbPath)
        c = conn.cursor()
        register_email = userObj.get_email()
        select_query = '''SELECT email FROM userList WHERE email="{}";'''.format(register_email)
        c.execute(select_query)

        # If fetchone() is called once, it can never be called again. Otherwise, ERROR.
        if c.fetchone() is None:
            print('This email does not exist.')
        else:
            c.execute(select_query)
            # Retrieves the result of the search query.
            found_email = c.fetchone()[0]
            print('execute query', found_email)
            # If email is in database, does not insert new data.
            if found_email == register_email:
                existEmail = True

        if existEmail:
            return 'This email exists!'

        # If email is not in database.
        else:

            insert_query = f'''INSERT INTO userList (email, username, password, role, phone_number, verified) VALUES 
            ("{userObj.get_email()}", "{userObj.get_username()}", "{userObj.get_password()}", "{userObj.get_role()}", "{userObj.get_ph_num()}", "{userObj.get_verified()}")'''
            # print(f'\n{insert_query} \n')
            c.execute(insert_query)
            conn.commit()

        print(existEmail)

    except sqlite3.Error as error:
        print("Error while connecting to sqlite;", error)
        conn = None

    finally:
        if conn:
            conn.close()
            # When the email exists.
            if existEmail is True:
                print('db_Register: FINISHED...\nEmail already exists!\n')
                return 'This email exists!'
            else:
                # If email does not exist, it will close.
                print('db_Register: FINISHED...\nThe connection has been closed.\n')
                return

    # If there is no connection to SQLITE Database.
    if conn is None:
        return 'Error connecting to SQLITE Database.'
    else:
        return True


def db_Login(user_email, orgPath):
    existEmail = False
    try:
        dbPath = os.path.join(orgPath, 'orgDB.db')
        conn = sqlite3.connect(dbPath)
        c = conn.cursor()

        # Select query to find the correct email.
        select_query = '''SELECT email FROM userList WHERE email="{}";'''.format(user_email)
        c.execute(select_query)
        # If fetchone() is called once, it can never be called again. Otherwise, ERROR.
        if c.fetchone() is None:
            print('This email does not exist.')
        else:
            c.execute(select_query)
            found_email = c.fetchone()[0]  # Gets my search result.
            print('execute query', found_email)
            # If email is in database, does not insert new data.
            if found_email == user_email:
                existEmail = True

        return existEmail

    except sqlite3.Error as error:
        print("Error while connecting to sqlite;", error)
        conn = None
    pass


# Enters a query into SQLITE database to find column data.
def db_Query(user_email, orgPath, column):
    print('\ndb_Query: STARTING...\n')
    existQuery = False
    try:
        dbPath = os.path.join(orgPath, 'orgDB.db')
        conn = sqlite3.connect(dbPath)
        c = conn.cursor()

        # Select query to find the correct email.
        selectQuery = f'''SELECT {column} FROM userList WHERE email="{user_email}";'''
        c.execute(selectQuery)
        # If fetchone() is called once, it can never be called again. Otherwise, ERROR.
        if c.fetchone() is None:
            print('This email does not exist.')
            print('\ndb_Query: FINISHING...\n')
            return None

        else:
            # Executes the query again to check for the result.
            c.execute(selectQuery)

            # Retrieves the result of the search query.
            queryResult = c.fetchone()[0]
            print('query result:', queryResult)

            # If email is in database, does not insert new data.
            if queryResult:
                existQuery = True
                print('\ndbQuery: FINISHING... Returning Result...\n')
                return queryResult
                # return existEmail
            else:
                pass

    except sqlite3.Error as error:
        print("Error while connecting to sqlite", error)

    if existQuery is False:
        print('\ndbQuery: FINISHING... Returning None...\n')
        return None


# Updates a column value in the database.
def db_Update(user_email, orgDBPath, column, value):
    print('\ndb_Update: STARTING...\n')
    print(f'\nUPDATING: {orgDBPath}\n')
    try:
        dbPath = os.path.join(orgDBPath, 'orgDB.db')
        conn = sqlite3.connect(dbPath)
        c = conn.cursor()

        # Select query to find the correct email.
        selectQuery = f'''UPDATE userList SET {column}="{value}" WHERE email="{user_email}";'''
        c.execute(selectQuery)

        print('\ndb_Update: FINISHING...\n')
        return

    except sqlite3.Error as error:
        print("Error while connecting to sqlite", error)

    finally:
        conn.commit()

# def db_Append(column, data):
#     if column == 'Organization':
#         try:
#             conn = sqlite3.connect('static/sqlite/cred_DB.db')
#             c = conn.cursor()

