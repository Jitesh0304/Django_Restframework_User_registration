# Base image
FROM python:3-alpine
# FROM python:3.8


# add ENV (PYTHONUNBUFFERED = 1) to show every loggs in you terminal
ENV PYTHONUNBUFFERED=1


# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Install the project dependencies
RUN pip install -r requirements.txt

# Copy the application code into the container
COPY . .

# Expose the port the Django application will be listening on
EXPOSE 8000

# Set environment variables, if necessary
# ENV MY_ENV_VAR=value

# Run the application
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
