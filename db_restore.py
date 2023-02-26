import io, os, sqlite3, sys, glob, shutil
import dropbox
from dropbox.files import WriteMode
from dropbox.exceptions import ApiError, AuthError
from zipfile import ZipFile
import os.path
from os.path import basename
import datetime


db_files = []
db_names = []

# Offline backup for SQLite.

# Goes through current directory and picks out SQLite files. (.db)
for f in os.listdir('.'):
    if os.path.isfile(f) and str(f).endswith('.db'):
        db_files.append(f)
# Appends the list of db file names into a list.

# Creates a list of the SQLite file names for backup.
for f in db_files:
    db_names.append(f[:-3]+'_BACKUP')

for i in db_files:
    print(i)

# Export Database into Backup Dump
def export_backup():
    for file in range(len(db_files)):
        # Start connection of DB file.
        conn = sqlite3.connect(db_files[file])

        # Directory for backup database files.
        backup_dir = 'Backup_Databases/' + db_names[file]
        # backup_dir = 'Backup_Databases/userStorage_BACKUP'

        # Checks if backup file contains anything.
        if len(os.path.dirname(backup_dir)) > 0:
            with io.open(backup_dir, 'w') as newfile:
                for line in conn.iterdump():
                    newfile.write('{}\n'.format(line))

        conn.close()

    print('Backup performed successfully!')
    print('Data Saved!')


# Import Backup Dump into Database
def import_backup():
    for file in range(len(db_files)):
        import_conn = sqlite3.connect(db_files[file])
        print(db_files[file])
        # Directory for backup database files.
        backup_dir = 'Backup_Databases/' + db_names[file]

        # Variable 'import_line' placeholds my SQL query for execution, into the database ON IMPORT.
        # count just keeps count. DUH.
        input_line = ''
        count = 0
        lineList = []

        if len(os.path.dirname(backup_dir)) > 0:
            with io.open(backup_dir, 'r') as readfile:
                for line in readfile:
                    lineList.append(line.strip())
                print(lineList)
                for line in lineList:
                    if len(line) > 0:
                        if line[-1] != ';':
                            input_line = '{} {}'.format(input_line, line).strip()
                            count += 1
                            print(input_line)

                        else:
                            print('Semi-colon end.')
                            try:
                                if count > 0:
                                    input_line = '{} {}'.format(input_line, line).strip()
                                    import_conn.execute(input_line)
                                    print('Input Line:\n{}\n'.format(input_line))

                                else:
                                    import_conn.execute(line)

                                input_line = ''
                                count = 0
                                print('ran')

                            except Exception as e:
                                print('ERROR MSG: {}'.format(e))
                                print('Error line:\n{}\n'.format(line))
                                print('This is the input line:\n{}\n'.format(input_line))
                                input_line = ''
                                count = 0
                                continue

        # Close connection upon completing file.
        import_conn.close()

    print('Import process successful.')
    print('Data Saved.')


# --------------------------------------------------------------------------------------

# Dropbox Backup Code

# Creates a connection to shake shack account's DROPBOX.
dbxConn = dropbox.Dropbox('-iTxlF4NFLcAAAAAAAAAASN62oqHCBBy824VjXPhgwcZ1tf06zC0lO0gVir74Lya')


# Won't work
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




def dbDownloadDropBox(file, destination=''):
    meta, file = dbxConn.files_download('/'+file)
    return file.content

def view_zip(file):
    zipObj = ZipFile(io.BytesIO(file))
    return zipObj.namelist()


def dbBackupPages():
    # Actual directory
    projPath = os.path.dirname(os.path.realpath(__file__))

    # Gets the app file directory.
    drive_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'drive')
    dirList = os.listdir(drive_path)
    print(dirList)

    # Checks if there is an organization with that email
    for index in dirList:
        orgFolder = index

        orgDirectory = os.path.join(drive_path, orgFolder, 'orgDB.db')

    # Database backup directory
    dbRecoveryPath = projPath+'/Backup_Databases/'

    # Database file names in main directory
    pages = db_files
    fname = str(datetime.datetime.now()).replace(':', '-').replace('.','-')
    result = dbxConn.files_list_folder('')
    if len(result.entries) >= 20:
        try:
            dbxConn.files_delete('/'+result.entries[0].name)
        except:
            pass
    zipObj = ZipFile(dbRecoveryPath+f'{fname}.zip','w')
    for page in pages:
        file = page
        zipObj.write(file, basename(file))
    zipObj.close()
    dbUploadDropBox(dbRecoveryPath+f'/{fname}.zip', f'/{fname}.zip')