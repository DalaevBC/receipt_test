from typing import List, Optional, Dict, Union, Tuple
from pydantic import BaseModel, validator


class User(BaseModel):
    id: int
    email: str
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

    class Config:
        orm_mode = True


class TokenData(BaseModel):
    email: str


class UserCreate(BaseModel):
    email: str
    password: str
    username: str


class UserNew(UserCreate):
    id: int
    username: Optional[str] = None


class Ingredient(BaseModel):
    description: str
    time: int
    photo: bytes


class RecipeCreate(BaseModel):
    title: str
    description: str
    ingredients: List[str]
    guide: List[Tuple[int, str, bytes]]

    @validator('ingredients')
    def validate_ingredients(cls, v):
        if not v:
            raise ValueError('Ingredients list cannot be empty')
        return v

    @validator('guide')
    def validate_guide(cls, v):
        if not v:
            raise ValueError('Guide list cannot be empty')
        return v


class RecipeSchema(BaseModel):
    id: int
    title: str
    description: str
    ingredients: List[str]
    guide: List[Ingredient]
    total_time: int
    rating: float = None
    author_id: int
    photo: bytes

    class Config:
        orm_mode = True


class RecipeUpdate(BaseModel):
    title: Optional[str]
    description: Optional[str]
    ingredients: Optional[List[str]]
    guide: Optional[List[Tuple[int, str, bytes]]]