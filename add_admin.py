from app import db, User, create_app
from werkzeug.security import generate_password_hash

# Создаем приложение Flask
app = create_app()

# Создаем нового пользователя с ролью администратора
def add_admin():
    admin_username = 'copp'
    admin_password = 'password'
    admin_email = 'admin@example.com'
    admin_phone = '1234567890'
    admin_full_name = 'Administrator'

    # Проверяем, существует ли уже пользователь с таким логином
    with app.app_context():
        existing_user = User.query.filter_by(username=admin_username).first()
        if existing_user:
            print(f"User with username '{admin_username}' already exists.")
            return

        # Создаем нового пользователя с хешированным паролем
        new_admin = User(
            username=admin_username,
            email=admin_email,
            phone=admin_phone,
            full_name=admin_full_name
        )
        new_admin.set_password(admin_password)
        db.session.add(new_admin)
        db.session.commit()
        print(f"Admin user '{admin_username}' added successfully.")

if __name__ == '__main__':
    add_admin()