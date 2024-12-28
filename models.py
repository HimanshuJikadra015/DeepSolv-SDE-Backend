from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Text, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker

from datetime import datetime
from passlib.context import CryptContext 



DATABASE_URL = "mysql+pymysql://instagram_user:Himanshu%40111207@localhost/instagram"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

follows = Table(
    'follows', Base.metadata,
    Column('follower_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('followed_id', Integer, ForeignKey('users.id'), primary_key=True)
)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(100), unique=True, index=True)
    hashed_password = Column(String(100))
    active_token = Column(String(500), nullable=True)
    posts = relationship("Post", back_populates="owner")

    followers = relationship(
        'User',
        secondary=follows,
        primaryjoin=id == follows.c.followed_id,
        secondaryjoin=id == follows.c.follower_id,
        backref='following'
    )

    def verify_password(self, password: str) -> bool:
        return pwd_context.verify(password, self.hashed_password)



class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    caption = Column(Text)
    post_url = Column(String(255))
    music_url = Column(String(255), nullable=True)
    category = Column(String(50))
    datetime_posted = Column(DateTime, default=datetime.utcnow)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="posts")




class Like(Base):
    __tablename__ = "likes"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    post_id = Column(Integer, ForeignKey("posts.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    datetime_liked = Column(DateTime, default=datetime.utcnow)




class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    post_id = Column(Integer, ForeignKey("posts.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    content = Column(Text)
    datetime_commented = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)