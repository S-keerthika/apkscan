from auth import init_db, create_user

init_db()

email = input("Admin email: ")
password = input("Admin password: ")

if create_user(email, password, role="admin", auto_verify=True):
    print("Admin account created successfully.")
else:
    print("Account already exists.")