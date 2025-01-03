# Use a Python base image
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy your project files into the container
COPY templates/index.html /app/templates/index.html
COPY app1.py /app/app1.py
COPY bg.jpg /app/bg.jpg
COPY script.py /app/script.py

# Install any dependencies (assuming you might need Flask or other packages)
RUN pip install flask

# Expose the port the app will run on
EXPOSE 5000

# Set the default command to run your app
CMD ["python", "app1.py"]
