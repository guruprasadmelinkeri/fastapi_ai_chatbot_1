from database import SessionLocal,User

from auth import hash

def create_admin(email: str, name: str, password: str):
    db = SessionLocal()
    try:
        if db.query(User).filter(User.email == email).first():
            print("User already exists")
            return
        admin_user = User(
            email=email,
            name=name,
            hashed_password=hash(password),
            role="admin"
        )
        db.add(admin_user)
        db.commit()
        print(f"Admin {email} created successfully.")
    finally:
        db.close()
