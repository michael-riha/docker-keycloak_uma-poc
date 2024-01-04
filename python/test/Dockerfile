# First stage - build and collect required packages
ARG base_image=python:3.10.7
FROM ${base_image}

RUN apt-get update && apt-get upgrade -y \
    && apt-get install --no-install-recommends -y \
        gcc \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --upgrade pip \
    && pip install -U wheel

ENV PYTHONUNBUFFERED 1
# Set the working directory to /app
WORKDIR /app
# Copy the current directory contents into the container at /app
COPY . /app

# Run the command to install any necessary dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Run *.py when the container launches
CMD ["python", "test.py"]
