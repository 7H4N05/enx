# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Install Flask (required for app1.py)
RUN pip install flask

# Expose the port that Flask will use
EXPOSE 5000

# Command to run your Flask app
CMD ["python", "app1.py"]
