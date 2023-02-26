from werkzeug.security import generate_password_hash, check_password_hash
import cryptography
import random


file_org_inputs = ['IT', 'Business', 'Engineering']


def verifyOrg(email, password, org_input, username):
    separator = '#$%&'
    # Checks if the input is an organisation list element.
    if org_input in file_org_inputs:
        # If the user's organisation is IT;
        if org_input == 'IT':
            orgFileRead = open('IT_Creds.txt', 'a+')
            filename = 'IT_Creds.txt'
            orgFileRead.seek(0)

        # Else if the user's organisation is Business;
        elif org_input == "Business":
            orgFileRead = open('Business_Creds.txt', 'a+')
            filename = 'Business_Creds.txt'
            orgFileRead.seek(0)

        elif org_input == 'Engineering':
            orgFileRead = open('Engineering_Creds.txt', 'a+')
            filename = 'Engineering_Creds.txt'
            orgFileRead.seek(0)

        if orgFileRead is not None and filename is not None:
            singleLine = orgFileRead.readline()

            # Check for an email in the org's file.
            count = 0
            flag = True
            if (separator in singleLine) and (email in singleLine):
                email_index = singleLine.find(email)
                print('This email exists in {}'.format(filename))
                print('Email is found at index {}.\n'.format(email_index))
                flag = False
                return 'Existing email.'
            else:
                print('Email not found in {}.'.format(filename))
                file_entry(separator, email, password, org_input, username)

            orgFileRead.close()


def file_entry(separator, email, password, organisation, username):
    if organisation == 'IT':
        fileOpen = open('IT_Creds.txt', 'a+')
    elif organisation == 'Business':
        fileOpen = open('Business_Creds.txt', 'a+')
    elif organisation == 'Engineering':
        fileOpen = open('Engineering_Creds.txt', 'a+')

    hash_pass = generate_password_hash(password)

    if fileOpen:
        line_input = username + separator + email + separator + hash_pass + separator
        fileOpen.write(line_input)
        print('File updated.')