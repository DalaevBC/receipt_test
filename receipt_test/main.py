from datetime import timedelta
from typing import List
import uvicorn as uvicorn
from fastapi import FastAPI, Depends, HTTPException
from starlette import status
import schemas
from db_connection import Session, get_db
from utils import authenticate_user, get_user_by_email, get_password_hash, \
    get_current_user, ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token, get_latest_user
from models import User, Recipe, Direction, Rating
from receipt_test.utils import commit

app = FastAPI()


@app.post("/api/token/")
async def login_for_access_token(email: str, password: str):
    return authenticate_user(email, password)


@app.post("/api/register/", response_model=schemas.UserNew)
async def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    last_user = get_latest_user
    db_user = get_user_by_email(user.email)
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    if last_user:
        id = db.query(User).order_by(User.id.desc()).first().id + 1
        print(id)
        db_user_new = User(email=user.email, hashed_password=hashed_password,
                           username=user.username, is_active=True, is_superuser=False,
                           is_verified=False, id=id)
    else:
        db_user_new = User(email=user.email, hashed_password=hashed_password,
                           username=user.username, is_active=True, is_superuser=False,
                           is_verified=False)

    commit(db, db_user_new)

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires)
    return {
        "id": db_user_new.id,
        "email": db_user_new.email,
        "password": user.password,
        "username": db_user_new.username,
        "access_token": access_token
    }


@app.post("/recipes/create/")
async def create_recipe(recipe: schemas.RecipeCreate, db=Depends(get_db), current_user: User = Depends(get_current_user)):
    new_guide = []
    new_ingredients = []
    total_time = 0

    for step in recipe.guide:
        time, description, photo = step
        if time is None or time == 0 or description is None or description == '':
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="time or description is NULL")
        id = db.query(Direction).order_by(Direction.id.desc()).first().id + 1
        direction = Direction(description=description, time=time, photo=photo, id=id)
        db.add(direction)
        db.flush()
        new_guide.append(int(id))
        total_time += time
        for i in recipe.ingredients:
            new_ingredients.append(i)

    recipe_db = Recipe(title=recipe.title, description=recipe.description,
                       ingredients=new_ingredients, guide=new_guide,
                       total_time=total_time, rating=0, author_id=current_user.id)
    commit(db, recipe_db)
    return recipe_db


@app.get("/recipes/{recipe_id}/")
async def get_recipe(recipe_id: int, db: Session = Depends(get_db)):
    recipe = db.query(Recipe).filter(Recipe.id == recipe_id).first()
    if not recipe:
        raise HTTPException(status_code=404, detail="Recipe not found")
    directions = db.query(Direction).filter(Direction.id.in_(recipe.guide)).all()
    guide = [[d.time, d.description, d.photo] for d in directions]
    return {
        "id": recipe.id,
        "title": recipe.title,
        "description": recipe.description,
        "ingredients": recipe.ingredients,
        "guide": guide,
        "total_time": recipe.total_time,
        "rating": recipe.rating,
        "author_id": recipe.author_id,
        "photo": recipe.photo
    }


@app.get("/recipes/", response_model=List[schemas.RecipeSchema])
def get_recipes(ingredient: str = '', time: int = 0, sort: str = '', asc: bool = True, stars: int = 0, asc_stars: bool = True, skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    recipes = db.query(Recipe).offset(skip).limit(limit).all()
    if ingredient:
        recipes = recipes.filter(Recipe.ingredients.contains([ingredient]))
    if time:
        recipes = recipes.filter(Recipe.total_time == time)
    if sort == "time":
        recipes = recipes.order_by(Recipe.total_time.asc() if asc else Recipe.total_time.desc())
    if sort == "sters":
        recipes = recipes.order_by(Recipe.rating.asc() if asc else Recipe.rating.desc())
    if stars:
        recipes = recipes.filter(Recipe.rating == stars)
    recipe_list = []
    for recipe in recipes:
        recipe_dict = recipe.__dict__
        recipe_dict.pop("_sa_instance_state", None)
        guide_list = []
        for guide_id in recipe.guide:
            guide = db.query(Direction).filter_by(id=guide_id).first()
            guide_list.append([guide.time, guide.description, guide.photo])
        recipe_dict["guide"] = guide_list
        recipe_list.append(recipe_dict)
    return recipe_list


@app.delete("/recipes/{recipe_id}/", status_code=status.HTTP_204_NO_CONTENT)
def delete_recipe(recipe_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    recipe = db.query(Recipe).filter(Recipe.id == recipe_id).first()
    if not recipe:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recipe not found")
    db.delete(recipe)
    db.commit()


@app.put("/recipes/{recipe_id}/")
async def update_recipe(recipe_id: int, recipe: schemas.RecipeUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    db_recipe = db.query(Recipe).filter(Recipe.id == recipe_id).first()
    if not db_recipe:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recipe not found")

    # Update Recipe table
    update_data = recipe.dict(exclude_unset=True)
    if "title" in update_data:
        db_recipe.title = update_data["title"]
    if "description" in update_data:
        db_recipe.description = update_data["description"]
    if "ingredients" in update_data:
        db_recipe.ingredients = update_data["ingredients"]
    if "photo" in update_data:
        db_recipe.photo = update_data["photo"]

    # Update Direction table
    directions = []
    total_time = 0
    for step in update_data["guide"]:
        time = step["time"]
        description = step["description"]
        photo = step["photo"]
        direction = Direction(time=time, description=description, photo=photo)
        commit(db, direction)
        directions.append(direction.id)
        total_time += time

    db_recipe.guide = directions
    db_recipe.total_time = total_time

    db.commit()
    db.refresh(db_recipe)
    return db_recipe


@app.post("/recipes/{recipe_id}/rating/")
def create_recipe_rating(recipe_id: int, grade: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    recipe = db.query(Recipe).filter(Recipe.id == recipe_id).first()
    if not recipe:
        raise HTTPException(status_code=404, detail="Recipe not found")
    if not 0 <= grade <= 5:
        raise HTTPException(status_code=400, detail="Grade must be between 0 and 5")
    rating = Rating(author_id=current_user.id, recipe_id=recipe_id, grade=grade)
    commit(db, rating)
    recipe.rating = round(sum(r.grade for r in recipe.ratings) / len(recipe.ratings), 2)
    commit(db, recipe)
    return {"id": rating.id, "author_id": rating.author_id, "recipe_id": rating.recipe_id, "grade": rating.grade}


if __name__ == '__main__':

    app = FastAPI()
    HOST_IP = "0.0.0.0"
    uvicorn.run("main:app", host=HOST_IP, port=3401)
