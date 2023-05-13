from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, LargeBinary, Float, ARRAY
from sqlalchemy.orm import relationship

from db_connection import Base


class User(Base):
    __tablename__ = "users"
    __table_args__ = {"extend_existing": True}
    id: int = Column(Integer, primary_key=True, index=True)
    email: str = Column(String, unique=True, index=True, nullable=False)
    username: str = Column(String, unique=True, nullable=True)
    hashed_password: str = Column(String(length=1024), nullable=False)
    is_active: bool = Column(Boolean, default=True, nullable=False)
    is_superuser: bool = Column(Boolean, default=False, nullable=False)
    is_verified: bool = Column(Boolean, default=False, nullable=False)


class Direction(Base):
    __tablename__ = "directions"
    __table_args__ = {"extend_existing": True}
    id = Column(Integer, primary_key=True, index=True)
    description = Column(String, nullable=False)
    time = Column(Integer, nullable=False)
    photo = Column(LargeBinary, nullable=True)


class Rating(Base):
    __tablename__ = "ratings"
    __table_args__ = {"extend_existing": True}
    id = Column(Integer, primary_key=True, index=True)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    recipe_id = Column(Integer, ForeignKey("recipes.id"), nullable=False)
    grade = Column(Integer, nullable=False)


class Recipe(Base):
    __tablename__ = "recipes"
    __table_args__ = {"extend_existing": True}
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True, nullable=False)
    description = Column(String, nullable=False)
    ingredients = Column(ARRAY(String), nullable=False)
    guide = Column(ARRAY(Integer), nullable=False)
    total_time = Column(Integer, nullable=False)
    rating = Column(Float, nullable=True)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    photo = Column(LargeBinary, nullable=True)

    ratings = relationship("Rating", backref="recipe")

    @property
    def rating(self):
        return self.ratings and round(sum(r.grade for r in self.ratings) / len(self.ratings), 2) or None

