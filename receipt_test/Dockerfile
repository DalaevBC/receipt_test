FROM python:3.9-slim-buster
WORKDIR /app
COPY Pipfile .
COPY Pipfile.lock .
RUN pip install pipenv && pipenv install --system
COPY . .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]