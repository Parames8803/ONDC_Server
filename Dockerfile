# Step 1: Start from the official Python image
FROM python:3.11

# Step 2: Install system dependencies for PyAudio
RUN apt-get update && apt-get install -y portaudio19-dev

# Step 3: Set the working directory in the container
WORKDIR /app

# Step 4: Copy the entire project directory into the container
COPY . /app

# Step 5: Install Python dependencies from requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Step 6: Expose the port your Flask app will run on (default Flask port is 5000)
EXPOSE 5000

# Step 7: Set the default command to run your Flask app
CMD ["python", "app.py"]
