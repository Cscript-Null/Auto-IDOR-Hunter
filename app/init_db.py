# app/init_db.py

from .database import engine
from .models import Base

def init_db():
    Base.metadata.create_all(bind=engine)
    print("数据库已初始化。")

if __name__ == "__main__":
    init_db()
