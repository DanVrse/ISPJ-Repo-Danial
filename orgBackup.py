import io, os, sqlite3, sys, glob, shutil
import dropbox
from dropbox.files import WriteMode
from dropbox.exceptions import ApiError, AuthError
from zipfile import ZipFile
from SQLite_Functions import *
import os.path
from os.path import basename
from datetime import datetime

# orgFiles = []
# orgNames = []

MAIN_DIR = os.path.dirname(__file__)
BASE_DIR = './ISPJ uploads/user'
BACKUP_DIR = './Backup_Databases'

# Offline backup for organizations

# Goes through current directory and picks out the folders.
orgNames = os.listdir(BASE_DIR)

# Goes through a range of folders in ISPJ Uploads
# for i in range(len(orgNames)):
#     print(f'{i+1}: {orgNames[i]}')


def backupFolderCreate():
    # Creates backup folders.
    for name in orgNames:
        backupDirFolder = f'{BACKUP_DIR}/{name}'
        if not os.path.exists(backupDirFolder):
            os.mkdir(backupDirFolder)
        else:
            # print(f'{backupDirFolder}: Already Exists')
            continue

    print('\nbackupFolderCreate: FINISHED!\n')


# Deletes past backup, to make way for current backups.
def deleteBackup():
    file_names = os.listdir(BACKUP_DIR)
    for file in file_names:
        filePath = os.path.join(BACKUP_DIR, file)
        if not file.endswith('.zip'):
            shutil.rmtree(filePath)
        else:
            continue


# Exports the folders into a backup.
def export_backup():
    # Delete files first before adding
    deleteBackup()

    backupFolderCreate()
    count = 1
    orgNamesLen = len(orgNames)
    for name in orgNames:
        # Start connection of DB file.
        path = os.path.join(BASE_DIR, name, 'orgDB.db')
        try:
            conn = sqlite3.connect(path)
        except sqlite3.Error as e:
            print(e)

        backupDirFolder = 'Backup_Databases/' + name
        backupFile = os.path.join(backupDirFolder, 'orgDB_BACKUP')

        if len(os.path.dirname(backupFile)) > 0:
            with io.open(backupFile, 'w') as newfile:
                for line in conn.iterdump():
                    newfile.write(f'{line}\n')

        conn.close()

        # Saves the organisation's JSON Files.
        jsonFiles = []
        for file in os.listdir(os.path.join(BASE_DIR, name)):
            if file.endswith('.json'):
                jsonFiles.append(file)

        for file in jsonFiles:
            src_file = os.path.join(BASE_DIR, name, file)
            des_file = backupDirFolder
            shutil.copy(src_file, des_file)
        print(f'Loading: {round(count/orgNamesLen, 2)*100}%...')
        count += 1

    print('Backup performed successfully!')
    print('Data saved!')


# Import Backup Dump into Database
def import_backup():

    # Goes through current directory and picks out the folders.
    orgNames = os.listdir(BASE_DIR)

    # Goes through all of the folder names.
    for name in orgNames:

        # Enters the organization folder, and connects to org's database.
        dbPath = os.path.join(BASE_DIR, name, 'orgDB.db')
        import_conn = sqlite3.connect(dbPath)
        print(import_conn)

        # Specifies the backup path to each respective folder.
        backupDirFolder = 'Backup_Databases/' + name
        orgDBFile = os.path.join(backupDirFolder, 'orgDB_BACKUP')

        # 'inputLine' variable is a placeholder for SQL queries for execution,
        # into the database on IMPORT.
        inputLine = ''
        count = 0
        lineList = []

        if len(os.path.dirname(backupDirFolder)) > 0:
            with io.open(orgDBFile, 'r') as readfile:
                for line in readfile:
                    lineList.append(line.strip())

                print(lineList)
                for line in lineList:
                    if len(line) > 0:
                        if line[-1] != ';':
                            inputLine = f'{inputLine} {line}'.strip()
                            count += 1
                            print(inputLine)

                        else:
                            print('Semi-colon end.')
                            try:
                                if count > 0:
                                    inputLine = f'{inputLine} {line}'.strip()
                                    import_conn.execute(inputLine)
                                    print(f'Input Line: {inputLine}')

                                else:
                                    import_conn.execute(line)

                                inputLine = ''
                                count = 0
                                print('ran')

                            except Exception as e:
                                print('ERROR MSG: {}'.format(e))
                                print('Error line:\n{}\n'.format(line))
                                print('This is the input line:\n{}\n'.format(inputLine))
                                inputLine = ''
                                count = 0
                                continue

        # Close connection upon completing file.
        import_conn.close()

    print('Import process successful.')
    print('Data Saved.')

# --------------------------------------------------------

# Dropbox Backup Code


# Creates a connection to Shake Shack Account's DROPBOX.
dbxConn = dropbox.Dropbox('-iTxlF4NFLcAAAAAAAAAASN62oqHCBBy824VjXPhgwcZ1tf06zC0lO0gVir74Lya')

# Takes zip folder from source path, to the Dropbox destination.
def dbUploadDropBox(source, destination):
    with open(source, 'rb') as upSource:
        print("Uploading {} to Dropbox as {}...".format(source, destination))
        try:
            dbxConn.files_upload(upSource.read(), destination)

        except ApiError as err:
            # This checks for the specific error where a user doesn't have
            # enough Dropbox space quota to upload this file
            if (err.error.is_path() and
                    err.error.get_path().reason.is_insufficient_space()):
                sys.exit("ERROR: Cannot back up; insufficient space.")
            elif err.user_message_text:
                print(err.user_message_text)
                sys.exit()
            else:
                print(err)
                sys.exit()


# Zips the folder of the BASE_DIR
def folderZIP():
    zip_name = 'backupZipDB ' + str(datetime.now()).replace(':', '-').replace('.', '-')
    zip_name = zip_name[:-7]
    dir_name = BASE_DIR

    shutil.make_archive(zip_name, 'zip', dir_name)
    src_dir = fr'{MAIN_DIR}/{zip_name}.zip'
    des_dir = BACKUP_DIR

    shutil.move(src_dir, des_dir)

    return zip_name


# Full backup process to DropBox
def dbBackupPages():
    # Actual directory
    projPath = os.path.dirname(os.path.realpath(__file__))

    # Database Backup Directory
    dbRecoveryPath = BACKUP_DIR

    # Database file names in main directory
    pages = orgNames
    # fname = str(datetime.now()).replace(':', '-').replace('.','-')
    # fname = fname[:-7]

    result = dbxConn.files_list_folder('')
    if len(result.entries) >= 10:
        for i in range(len(result.entries)-10):
            try:
                dbxConn.files_delete('/'+result.entries[0].name)
                print('deleted')
            except:
                pass
    # zipObj = ZipFile(dbRecoveryPath+f'{fname}.zip','w')
    # for page in pages:
    #     file = page
    #     zipObj.write(file, basename(file))
    # zipObj.close()

    finalZipName = folderZIP()
    dbUploadDropBox(dbRecoveryPath+f'/{finalZipName}.zip', f'/{finalZipName}.zip')

# export_backup()
# dbBackupPages()



