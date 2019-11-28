import os
import time
import getpass
import base64
import hashlib
import binascii
from zipfile import ZipFile
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Personal project to serve as an exercise.
# This script simply creates a file of usernames and associated salted password hashes.
# It also has methods to check username associated passwords for authentication
# as well as encrypt/decrypt user directories.

# Error codes
success = 0x0
invalid_access = 0x1
requestor_does_not_exist = 0x2
user_does_not_exist = 0x3
user_already_exists = 0x4
bad_name_format = 0x5
shadow_fail = 0x6
invalid_decryption_key = 0x7
already_encrypted = 0x8
formating_error = 0xBADBEEF
silent_success = 0xCAFE
authentication_failed = 0xDEADBEEF

# Dictionary where error codes are keys.
# Dictionary used to facilitate informing the user of output.
# Success is intended to change based on function output.
res_dict = {
    success: "",
    invalid_access: "Permission denied, invalid access",
    requestor_does_not_exist: "Authorizing user does not exist",
    user_does_not_exist: "User does not exist",
    user_already_exists: "User already exists",
    bad_name_format: "Usernames or groupnames with colons are not allowed",
    shadow_fail: "Cannot create temporary shadow file",
    invalid_decryption_key: "Decryption failed: the decryption key you entered is not correct",
    already_encrypted: "The user's directory is already encrypted",
    formating_error: "Formating error",
    silent_success: "",
    authentication_failed: "Authentication failed"
}

function_descriptions = {
    'adduser': 'adduser Usage:\nadduser new_username new_user_password access_level authorizing_party\nacc'
    +'ess_level can be anything, unless a non-admin is authorizing a new admin user',
    'access': 'access Usage: access username encrypt Or, alternatively: access username decrypt',
    'last': 'last Usage: last n . Returns up to the last n commands entered where n is an integer'
}

command_history = -1
last_commands = []
try_again = False

# I defined shadow_handler as an object that parses each entry
# in the shadow file (a file that houses password hases)
# The format of each entry is username:levelofaccess:hashed_password:password_salt
class shadow_handler:

    def __init__(self, metadata):
        self.uname = metadata[0]
        self.type = metadata[1]
        self.hash = metadata[2]
        self.salt = metadata[3].strip()

    def user(self):
        return self.uname

    def level(self):
        return self.type

    def conv_salt(self):
        return binascii.unhexlify(self.salt.encode('utf-8'))

# Function that adds or removes entries in the shadow file
def shadow_write(uname, passwd, type, mode = None):
    global user_already_exists
    global success
    global shadow_fail

    if mode == 'remove':
        with open('accounts/shadow', 'r') as pf:
            data = b''
            line = pf.readline()
            while line:
                user = shadow_handler(line.split(':'))
                if user.uname != uname:
                    data += line.encode()
                line = pf.readline()
        try:
            temp = open('accounts/shadow_temp', 'wb')
            temp.write(data)
            temp.close()
        except:
            return shadow_fail

        os.system('rm accounts/shadow; mv accounts/shadow_temp accounts/shadow')
        global resmap
        res_dict[success] = ''+(uname+' removed')
        return success

    salt = os.urandom(24)
    hash = hashlib.pbkdf2_hmac('sha256', passwd.encode(), salt, 100000)

    with open("accounts/shadow", "a") as p_file:
        p_file.write(uname+':'+type+':'+hash.hex()+':'+binascii.hexlify(salt).decode('utf-8')+'\n')

    global resmap
    res_dict[success] = ''+(uname+' added as a '+type)
    return success

# Function that checks if system has been created
# If it isn't will ask for an administrator name and password
def init_sys():

    if os.path.exists('accounts/shadow'):
        return

    uname = str(input('Root name: '))
    not_verified = True

    while not_verified:
        pass1 = str(getpass.getpass(prompt='Password: '))
        pass2 = str(getpass.getpass(prompt='Verify Password: '))
        if pass1 == pass2:
            not_verified = False
        else:
            print('Password dosen\'t match, try again')

    os.system('mkdir accounts; mkdir lib; mkdir accounts/shadow_master; mkdir accounts/shadow_master/'+uname+'; touch accounts/shadow; mkdir accounts/'+uname)
    shadow_write(uname, pass1, 'admin')

    master_key = str(input('Set master key -- System will be compromised if key is compromised? y/n: '))

    if master_key == 'Y' or master_key == 'y':
        not_verified = True
        os.system('touch lib/keys_true')
        while not_verified:
            pass1 = str(getpass.getpass(prompt='Master Key: '))
            pass2 = str(getpass.getpass(prompt='Verify Master Key: '))
            if pass1 == pass2:
                not_verified = False
            else:
                print('Password dosen\'t match, try again')
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open('lib/'+'private_key.pem', 'wb') as f:
            f.write(Fernet(gen_encyption_key(uname, pass1)).encrypt(pem))

        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open('lib/public_key.pem', 'wb') as f:
            f.write(pem)
    os.system('touch lib/public_key.pem; touch lib/private_key.pem')

# Looks for an entry in the shadow file
# If there is one, it returns a shadow_handler object
def getUserData(uname, user_list = None):
    global user_does_not_exist
    u_list = []
    if user_list == True:
        with open('accounts/shadow') as pf:
            line = pf.readline()
            while line:
                u_list.append(shadow_handler(line.split(':')))
                line = pf.readline()
        return u_list
    with open('accounts/shadow') as pf:
        line = pf.readline()
        while line:
            user = shadow_handler(line.split(':'))
            if user.uname == uname:
                return user
            line = pf.readline()

    return user_does_not_exist

def trackUser(uname):
    global try_again
    if os.path.exists('accounts/_'+uname+'.frost'):
        try_again = True
        return

    global command_history
    global last_commands
    file_path = 'accounts/'+uname+'/.command_history'
    if os.path.exists(file_path) != True:
        os.system('touch '+file_path)
    with open(file_path, 'r') as populate:
        line = populate.readline()
        while line:
            last_commands.append(line)
            line = populate.readline()
    command_history = open(file_path, 'a')
    try_again = False

def stopTrackUser(uname):
    global command_history
    command_history.close()

def addCommand(command):
    global command_history
    global last_commands
    command_history.write(command+'\n')
    last_commands.append(command+'\n')

def last(uname_caller, num_entries):
    global last_commands
    global silent_success

    num_entries = int(num_entries)
    rev = last_commands[::-1]
    for i in range(0, len(rev)):
        if num_entries <= i:
            break
        print(rev[i], end = "")
    return silent_success

# Finds the associated entry in the shadow file
# and if it exists generates a hash using the
# provided password and the salt from the
# shadow file entry
def authenticate(uname, passwd=None):
    global user_does_not_exist
    user = getUserData(uname)

    if user != user_does_not_exist:
        if passwd == None:
            passwd = str(getpass.getpass(prompt='Password for '+str(uname)+': '))
        return str(hashlib.pbkdf2_hmac('sha256', passwd.encode(), user.conv_salt(), 100000).hex()) == user.hash
    else:
        return user_does_not_exist

# Verifies that a username dosen't contain
# our delimiter for our shadow file entry, a colon
# If we didn't check, you could employ an injection attack
# that allows non-admin users to gain admin privileges
# by creating a new user whose username is a modified copy
# of their own shadow file entry
def checkUsername(uname):
    for i in range(0, len(uname)):
        if uname[i] == ':':
            return bad_name_format
    return False

def gen_encyption_key(uname, passwd):
    user = getUserData(uname)
    return base64.urlsafe_b64encode(hashlib.pbkdf2_hmac('sha256', passwd.encode(), user.conv_salt(), 50000))

def encrypt(fname, fer):

    # Add data prefix check later on
    if fname.endswith(".frost"):
        return
    with open(fname, 'rb') as f:
        data = f.read()

    enc = fer.encrypt(data)

    with open(fname+'.frost', 'wb') as f:
        f.write(enc)

    os.remove(fname)

def decrypt(fname, fer):

    global invalid_decryption_key
    if not fname.endswith(".frost"):
        return
    with open(fname, 'rb') as f:
        data = f.read()

    try:
        enc = fer.decrypt(data)
    except InvalidToken as e:
        return invalid_decryption_key

    with open(fname[:-6], 'wb') as f:
        f.write(enc)

    os.remove(fname)

def access(uname_caller, uname, option):
    global authentication_failed
    global invalid_access
    global user_does_not_exist
    global formating_error
    global silent_success
    global invalid_decryption_key
    global already_encrypted

    mk = b''
    tl = b''
    ed = b''
    if uname_caller != uname and option == 'decrypt' and os.path.exists('lib/keys_true'):
        caller_info = getUserData(uname_caller)
        if caller_info.level() == 'admin':
            pass1 = str(getpass.getpass(prompt='Enter Master Key: '))
            mk_key = Fernet(gen_encyption_key(uname_caller, pass1))


            with open('lib/private_key.pem', 'rb') as pk:
                try:
                    mk = mk_key.decrypt(pk.read())
                    private_key = serialization.load_pem_private_key(
                        mk,
                        password=None,
                        backend=default_backend()
                    )
                except InvalidToken as e:
                    return invalid_decryption_key

            with open('accounts/shadow_master/'+uname+'/tl', 'rb') as pk:
                tl = private_key.decrypt(
                    pk.read(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
            with open('accounts/shadow_master/'+uname+'/ed', 'rb') as pk:
                ed = private_key.decrypt(
                    pk.read(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
        else:
            return invalid_access
    else:
        password = str(getpass.getpass(prompt='Password for '+str(uname)+': '))

        certification = authenticate(uname, passwd=password)

        if not certification:
            return authentication_failed
        elif certification == user_does_not_exist:
            return user_does_not_exist

        not_verified = True
        while not_verified:
            pass1 = str(getpass.getpass(prompt='Choose Encryption Key or Enter Decryption Key: '))
            pass2 = str(getpass.getpass(prompt='Verify the Encryption or Decryption Key: '))
            if pass1 == pass2:
                not_verified = False
            else:
                print('Password dosen\'t match, try again')


        tl = gen_encyption_key(uname, pass1)
        ed = gen_encyption_key(uname, password)


    top_layer = Fernet(tl)
    enc_dec_model = Fernet(ed)

    if option == 'encrypt':
        if os.path.exists('accounts/_'+uname+'.frost'):
            return already_encrypted

        os.system('touch accounts/_'+uname+'.zip')
        zip = ZipFile('accounts/_'+uname+'.zip', 'w')

        print('encrypting...')
        for root, dirs, files, in os.walk('accounts/'+uname):
            for file in files:
                f = root+'/'+file
                encrypt(f, enc_dec_model)
                zip.write(f+'.frost')

        zip.close()
        os.system('mv accounts/_'+uname+'.zip '+'accounts/_'+uname)
        encrypt('accounts/_'+uname, top_layer)
        os.system('rm -r accounts/'+uname)
        if os.path.exists('lib/public_key.pem'):

            with open("lib/public_key.pem", "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )

            try:
                file_path = 'accounts/shadow_master/'+uname+'/tl'
                temp = open(file_path+'_temp', 'wb')
                encrypted = public_key.encrypt(
                    tl,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                temp.write(encrypted)
                temp.close()
                os.system('rm '+file_path+'; mv '+file_path+'_temp '+file_path)
            except:
                return shadow_fail
            try:
                file_path = 'accounts/shadow_master/'+uname+'/ed'
                encrypted = public_key.encrypt(
                    ed,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                temp = open(file_path+'_temp', 'wb')
                temp.write(encrypted)
                temp.close()
                os.system('rm '+file_path+'; mv '+file_path+'_temp '+file_path)
            except:
                return shadow_fail


    elif option == 'decrypt':

        if decrypt('accounts/_'+uname+'.frost', top_layer) == invalid_decryption_key:
            return invalid_decryption_key

        # After decrypting zip file, unzip it and process contents for individual file decryption
        os.system('mv accounts/_'+uname+' accounts/target_temp.zip; unzip accounts/target_temp.zip -d '+'accounts/'+uname)
        os.system('rm accounts/target_temp.zip')
        os.system('cp -r accounts/'+uname+'/accounts/'+uname+' accounts/temp_'+uname+'; rm -r accounts/'+uname)
        os.system('mv accounts/temp_'+uname+' accounts/'+uname)

        print('decrypting')
        for root, dirs, files, in os.walk('accounts/'+uname):
            for file in files:
                decrypt(root+'/'+file, enc_dec_model)

    else:
        return formating_error

    return silent_success

# Verifies that a user can be added at the requested
# level and checks for other edge cases.
def addUser(uname_caller, uname, passwd, type):
    global invalid_access
    global user_does_not_exist
    global authentication_failed
    global bad_name_format
    global user_already_exists
    requestor = uname_caller

    if getUserData(uname) != user_does_not_exist:
        return user_already_exists

    if checkUsername(uname) == bad_name_format or checkUsername(type) == bad_name_format:
        return bad_name_format

    check = getUserData(requestor)
    if check != user_does_not_exist:
        if type == 'admin' and check.level() != 'admin':
            return invalid_access
    else:
        return user_does_not_exist

    if not authenticate(requestor):
        return authentication_failed

    user_dir = 'accounts/'+uname
    if os.path.exists(user_dir):
        return user_already_exists

    make_dir = 'mkdir '+user_dir

    os.system(make_dir)
    os.system('mkdir accounts/shadow_master/'+uname)
    return shadow_write(uname, passwd, type)

def changePass(uname_caller, uname):
    global authentication_failed
    global user_does_not_exist
    global shadow_fail
    global invalid_decryption_key

    user_data = getUserData(uname)

    auth = access(uname, "decrypt")
    if not auth:
        return authentication_failed
    elif auth == user_does_not_exist:
        return user_does_not_exist
    elif auth == invalid_decryption_key:
        return invalid_decryption_key

    not_verified = True

    while not_verified:
        pass1 = str(getpass.getpass(prompt='New Password: '))
        pass2 = str(getpass.getpass(prompt='Verify New Password: '))
        if pass1 == pass2:
            not_verified = False
        else:
            print('Password dosen\'t match, try again')

    if shadow_write(uname, None, None, mode='remove') == shadow_fail:
        return shadow_fail

    option = str(input('Encrypt? y/n: '))
    if option == 'y' or option == 'Y':
        access(uname, 'encrypt')
    return shadow_write(uname, pass1, user_data.level())

def removeUser(uname_caller, uname):
    global authentication_failed
    global user_does_not_exist

    option = str(input('Save files? y/n: '))

    if option == 'y' or option == 'Y':
        auth = access(uname, 'decrypt')
        if auth != authentication_failed and auth != user_does_not_exist:
            return shadow_write(uname, None, None, mode='remove')
        else:
            return auth
    else:
        print('Authenticate your account to remove the account and associated files')
        auth = authenticate(uname)
        if auth == True:
            user_dir = 'accounts/'+uname
            if os.path.exists(user_dir):
                os.system('rm -r '+user_dir)
            if os.path.exists('accounts/_'+uname+'.frost'):
                os.system('rm -r '+'accounts/_'+uname+'.frost')
            return shadow_write(uname, None, None, mode='remove')
        elif auth == False:
            return authentication_failed
        else:
            return user_does_not_exist

def showUsers(uname_caller):
    global res_dict
    global success
    u_list = getUserData("Dummy_Name", user_list = True)
    result = ''
    for user in u_list:
        result += user.uname+' '
    res_dict[success] = result
    return success

# Utility function to display return message
def info_result(result):
    global silent_success
    global formating_error
    global res_dict
    global function_descriptions

    if result[0] == silent_success:
        return
    elif result[0] == formating_error:
        try:
            print(res_dict[result[0]]+'\n'+function_descriptions[result[1]])
        except KeyError:
            print('No function information entry for '+result[1])
        return
    print(res_dict[result[0]])

def login():

    global user_does_not_exist

    username = str(input("Username: "))

    if getUserData(username) == user_does_not_exist:
        return ('user_does_not_exist', username)

    wrong_attempts = 0
    not_logged_in = True

    while not_logged_in:
        if wrong_attempts == 3:
            return ('failed', username)
        password = str(getpass.getpass(prompt='Enter Password: '))
        if authenticate(username, passwd=password) == True:
            not_logged_in = False
        else:
            time.sleep(1.6)
            print('Password is incorrect, try again')
            wrong_attempts += 1

    return('success', username)


def clear(uname_caller):
    global silent_success
    os.system("clear")
    return silent_success


# A list of commands for our interactive shell
commands = {'adduser': addUser, 'users': showUsers,
    'access': access, 'clear': clear, 'passwd': changePass,
    'rmuser': removeUser, 'last': last}

# Shell
def driver():
    global commands

    session = login()
    if session[0] == 'failed':
        print('Too many wrong password attempts')
        return
    elif session[0] == 'user_does_not_exist':
        print('User does not exist')
        return

    user = session[1]

    trackUser(user)

    close = False
    command_list = ['adduser', 'users', 'commands', 'exit', 'access', 'clear', 'last']
    print('Welcome '+user+', type commands for a list of commands and exit to quit.')
    while not close:
        global try_again
        if try_again:
            trackUser(user)
        command = str(input('*** '))
        args = command.split()
        if args == []:
            continue
        if args[0] in commands and len(args) > 1:
            try:
                result = (commands[args[0]](user,*args[1:]), '')
                if result[0] == formating_error:
                    result = (formating_error, args[0])
            except TypeError as e:
                result = (formating_error, args[0])
            info_result(result)
        elif args[0] in commands:
            try:
                result = (commands[args[0]](user), '')
            except TypeError as e:
                result = (formating_error, args[0])
            info_result(result)
        elif args[0] == 'commands':
            for item in command_list:
                print(item)
        elif args[0] == 'exit':
            stopTrackUser(user)
            close = True
            continue
        else:
            print('Command not found')
        if try_again:
            continue
        addCommand(command)

# The only two functions that are actually
# called directly when running this script
init_sys()
driver()
