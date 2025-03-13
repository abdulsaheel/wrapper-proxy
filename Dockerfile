# Use an official Python image as a base
FROM python:3.9

# Set environment variables to prevent Python from writing .pyc files and buffering output
ENV PYTHONUNBUFFERED 1

# Set working directory
WORKDIR /app

# Install required system dependencies (NGINX)
RUN apt-get update && apt-get install -y nginx && rm -rf /var/lib/apt/lists/*

# Copy requirements file and install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Flask application
COPY . /app/

# Create an initial NGINX config directory
RUN mkdir -p /etc/nginx/conf.d/

# Remove default NGINX site
RUN rm -f /etc/nginx/sites-enabled/default

# Overwrite the default NGINX HTML file with "test"
RUN echo "test" > /var/www/html/index.nginx-debian.html

# Expose ports for Flask (5000) and NGINX (80, 443)
EXPOSE 5000 80 443

# Start both NGINX and the Flask application
CMD service nginx start && python app.py