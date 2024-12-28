import logging
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from models import Base, engine, SessionLocal, User, Post, Like, Comment
from pydantic import BaseModel
from typing import List, Optional
from passlib.context import CryptContext
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from sqlalchemy.exc import IntegrityError


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()



SECRET_KEY = "mynameisthesecretkeyHimanshu"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class Token(BaseModel):
    access_token: str
    token_type: str
    user_id: int
    username: str



class TokenData(BaseModel):
    username: str | None = None

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    email: str

    class Config:
        orm_mode = True

class PostCreate(BaseModel):
    caption: str
    post_url: str
    music_url: str | None = None
    category: str



class PostOut(BaseModel):
    id: int
    caption: str
    post_url: str
    music_url: str
    category: str
    datetime_posted: datetime
    owner_id: int

class UserProfile(BaseModel):
    id: int
    username: str
    email: str
    posts: List[PostOut]
    followers_count: int
    following_count: int
    followers: List[UserOut]
    following: List[UserOut]

    class Config:
        orm_mode = True



class UserOut(BaseModel):
    id: int
    username: str
    email: str
    class Config:
        orm_mode = True
        from_attributes = True

class LikeOut(BaseModel):
    id: int
    post_id: int
    user_id: int
    datetime_liked: datetime
    class Config:
        orm_mode = True

class CommentCreate(BaseModel):
    content: str

class CommentOut(BaseModel):
    id: int
    user_id: int
    content: str
    datetime_commented: datetime

    class Config:
        orm_mode = True



class PostDetail(BaseModel):
    id: int
    caption: str
    post_url: str
    music_url: str
    category: str
    datetime_posted: datetime
    owner: UserOut
    likes_count: int
    comments_count: int
    comments: List[CommentOut]

    class Config:
        orm_mode = True

class CommentWithUserOut(BaseModel):
    id: int
    user: UserOut
    content: str
    datetime_commented: datetime

    class Config:
        orm_mode = True
        from_attributes = True


class FeedPostOut(BaseModel):
    id: int
    caption: str
    post_url: str
    music_url: str
    category: str
    datetime_posted: datetime
    owner: UserOut

    class Config:
        from_attributes = True

class UserSearchOut(BaseModel):
    id: int
    username: str
    email: str

    class Config:
        from_attributes = True

class SearchPostOut(BaseModel):
    id: int
    caption: str
    post_url: str
    music_url: str
    category: str
    datetime_posted: datetime
    owner: UserOut

    class Config:
        from_attributes = True



def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.get("/")
def read_root():
    return {"message": "Welcome to the Instagram-like API"}


# register user
@app.post("/users/", response_model=UserOut)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    try:
        existing_user = db.query(User).filter((User.email == user.email) | (User.username == user.username)).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Email or username already registered")

        hashed_password = pwd_context.hash(user.password)
        db_user = User(username=user.username, email=user.email, hashed_password=hashed_password)
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        return db_user
    except IntegrityError as e:
        db.rollback()
        logger.error(f"IntegrityError: {e}")
        raise HTTPException(status_code=400, detail="Email or username already registered")
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error creating user: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")



# login user
@app.post("/login", response_model=Token)
def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not user.verify_password(form_data.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    user.active_token = access_token
    db.commit()

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "username": user.username
    }



def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception

    return user



# post 
@app.post("/posts/", response_model=PostOut)
def create_post(
    post: PostCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        db_post = Post(**post.dict(), owner_id=current_user.id)
        db.add(db_post)
        db.commit()
        db.refresh(db_post)
        return db_post
    except Exception as e:
        logger.error(f"Error creating post: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


# user profile
@app.get("/users/{username}", response_model=UserProfile)
def view_user_profile(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "posts": user.posts,
        "followers_count": len(user.followers),
        "following_count": len(user.following),
        "followers": user.followers,
        "following": user.following
    }


# follow 
@app.post("/follow/{username}", response_model=UserOut)
def follow_user(username: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    user_to_follow = db.query(User).filter(User.username == username).first()
    if not user_to_follow:
        raise HTTPException(status_code=404, detail="User not found")
    if user_to_follow == current_user:
        raise HTTPException(status_code=400, detail="You cannot follow yourself")
    if user_to_follow in current_user.following:
        raise HTTPException(status_code=400, detail="You are already following this user")
    current_user.following.append(user_to_follow)
    db.commit()
    return user_to_follow

# unfollow
@app.post("/unfollow/{username}", response_model=UserOut)
def unfollow_user(username: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    user_to_unfollow = db.query(User).filter(User.username == username).first()
    if not user_to_unfollow:
        raise HTTPException(status_code=404, detail="User not found")
    if user_to_unfollow == current_user:
        raise HTTPException(status_code=400, detail="You cannot unfollow yourself")
    if user_to_unfollow not in current_user.following:
        raise HTTPException(status_code=400, detail="You are not following this user")
    current_user.following.remove(user_to_unfollow)
    db.commit()
    return user_to_unfollow


# my posts with pagination
@app.get("/my-posts/", response_model=List[PostOut])
def get_my_posts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    skip: int = 0,
    limit: int = 10
):
    posts = db.query(Post).filter(Post.owner_id == current_user.id).offset(skip).limit(limit).all()
    return posts


# others posts with pagination
@app.get("/other-posts/", response_model=List[PostOut])
def get_other_posts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    skip: int = 0,
    limit: int = 10
):
    posts = db.query(Post).filter(Post.owner_id != current_user.id).offset(skip).limit(limit).all()
    return posts


# all details of a post
@app.get("/posts/{post_id}", response_model=PostDetail)
def get_post_details(post_id: int, db: Session = Depends(get_db)):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    likes_count = db.query(Like).filter(Like.post_id == post_id).count()
    comments = db.query(Comment).filter(Comment.post_id == post_id).all()
    comments_count = len(comments)
    
    return {
        "id": post.id,
        "caption": post.caption,
        "post_url": post.post_url,
        "music_url": post.music_url,
        "category": post.category,
        "datetime_posted": post.datetime_posted,
        "owner": post.owner,
        "likes_count": likes_count,
        "comments_count": comments_count,
        "comments": comments
    }


# like post
@app.post("/posts/{post_id}/like", response_model=LikeOut)
def like_post(post_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    existing_like = db.query(Like).filter(Like.post_id == post_id, Like.user_id == current_user.id).first()
    if existing_like:
        raise HTTPException(status_code=400, detail="You have already liked this post")
    
    like = Like(post_id=post_id, user_id=current_user.id)
    db.add(like)
    db.commit()
    db.refresh(like)
    return like



# get list of users liked a post with pagination
@app.get("/posts/{post_id}/likes", response_model=List[UserOut])
def get_post_likes(
    post_id: int,
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 10
):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    likes = db.query(Like).filter(Like.post_id == post_id).offset(skip).limit(limit).all()
    user_ids = [like.user_id for like in likes]
    users = db.query(User).filter(User.id.in_(user_ids)).all()
    
    return users


# comment on post
@app.post("/posts/{post_id}/comment", response_model=CommentOut)
def comment_on_post(
    post_id: int,
    comment: CommentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    new_comment = Comment(
        post_id=post_id,
        user_id=current_user.id,
        content=comment.content
    )
    db.add(new_comment)
    db.commit()
    db.refresh(new_comment)
    return new_comment


#  get list of users with comments on a post with pagination
@app.get("/posts/{post_id}/comments", response_model=List[CommentWithUserOut])
def get_post_comments(
    post_id: int,
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 10
):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    
    comments = db.query(Comment).filter(Comment.post_id == post_id).offset(skip).limit(limit).all()
    comments_with_users = []
    for comment in comments:
        user = db.query(User).filter(User.id == comment.user_id).first()
        user_out = UserOut.from_orm(user)
        comments_with_users.append(CommentWithUserOut(
            id=comment.id,
            user=user_out,
            content=comment.content,
            datetime_commented=comment.datetime_commented
        ))
    
    return comments_with_users


# feed based on following of a user with pagination
@app.get("/feed/", response_model=List[FeedPostOut])
def get_user_feed(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    skip: int = 0,
    limit: int = 10
):
    following_ids = [user.id for user in current_user.following]
    
    posts = db.query(Post).filter(Post.owner_id.in_(following_ids)).order_by(Post.datetime_posted.desc()).offset(skip).limit(limit).all()
    
    return posts





#  search username
@app.get("/search/users/", response_model=List[UserSearchOut])
def search_users(
    query: str,
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 10
):
    users = db.query(User).filter(User.username.ilike(f"%{query}%")).offset(skip).limit(limit).all()
    return users



# filter posts based on caption, category, time with pagination
@app.get("/search/posts/", response_model=List[SearchPostOut])
def search_posts(
    query: str,
    db: Session = Depends(get_db),
    skip: int = 0,
    limit: int = 10,
    category: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None
):
    posts_query = db.query(Post).filter(Post.caption.ilike(f"%{query}%"))
    
    if category:
        posts_query = posts_query.filter(Post.category == category)
    
    if start_date:
        posts_query = posts_query.filter(Post.datetime_posted >= start_date)
    
    if end_date:
        posts_query = posts_query.filter(Post.datetime_posted <= end_date)
    
    posts = posts_query.offset(skip).limit(limit).all()
    return posts