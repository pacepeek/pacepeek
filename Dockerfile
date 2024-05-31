FROM python:3.10.9-slim

# Set the working directory to /app
WORKDIR /app

# Copy the requirements file
COPY requirements.txt .

# Install the dependencies
RUN pip install -r requirements.txt

# Copy the application code
COPY . .

# Set the environment variable for Flask
ENV FLASK_APP=app.py
ENV FLASK_ENV=development

# Expose the port
EXPOSE 5000

# Run the command to start the development server
CMD ["flask", "run", "--host=0.0.0.0"]
