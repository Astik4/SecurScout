FROM python:3.11-slim

# Install Nmap binary and clean apt cache to keep container small
RUN apt-get update && \
    apt-get install -y nmap && \
    rm -rf /var/lib/apt/lists/*

# Set up project directory
WORKDIR /app

# Copy all project files into the container
COPY . /app

# Install the Python package and its dependencies
RUN pip install --no-cache-dir .

# Create a non-root user and group for security compliance
RUN groupadd -r -g 10001 appuser && \
    useradd -r -u 10001 -g appuser -d /app -s /sbin/nologin appuser

# Change ownership of the app directory to the non-root user
RUN chown -R appuser:appuser /app

# Switch to the non-root user
USER appuser

# Expose the Flask web server port
EXPOSE 5000

# Start the web UI server binding to all network interfaces
CMD ["securscout", "--web", "--host", "0.0.0.0"]
