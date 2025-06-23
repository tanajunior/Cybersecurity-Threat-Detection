    # Use the official Python image from Docker Hub as the base image
    # We choose a specific version (3.10-slim-buster) for stability and smaller image size
    FROM python:3.10-slim-buster

    # Set the working directory inside the container
    # All subsequent commands will be executed relative to this directory
    WORKDIR /app

    # Copy the Python dependency files into the container
    # This step is optimized for Docker caching: if requirements.txt doesn't change,
    # Docker won't re-run pip install, speeding up subsequent builds.
    COPY requirements.txt .

    # Install the Python dependencies specified in requirements.txt
    # The --no-cache-dir flag helps to keep the image size smaller
    RUN pip install --no-cache-dir -r requirements.txt

    # Copy all remaining project files into the working directory (/app) in the container
    # This includes app.py, the trained model, scalers, and preprocessed data
    COPY . .

    # Expose the port that the Flask application will listen on
    # Cloud Run expects the application to listen on the port defined by the PORT environment variable
    ENV PORT 8080
    EXPOSE $PORT

    # Define the command to run your Flask application
    # We use Gunicorn, a production-ready WSGI HTTP server, for serving Flask.
    # It's more robust and performs better than Flask's built-in development server.
    # -b 0.0.0.0:$PORT: Binds Gunicorn to all network interfaces on the specified port
    # --timeout 120: Sets a generous timeout for requests (e.g., for long model predictions)
    # --workers 2: Configures 2 worker processes for handling requests concurrently
    # --threads 4: Configures 4 threads per worker for I/O operations
    # app:app: Specifies that the Flask application instance 'app' is found in the 'app.py' module
    CMD exec gunicorn --bind 0.0.0.0:$PORT --timeout 120 --workers 2 --threads 4 app:app
    
