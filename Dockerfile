FROM python:3.10

# Install git to clone the repository
RUN apt-get update && apt-get install -y git protobuf-compiler && apt-get install -y openjdk-21-jdk && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /goldrush

ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV PATH="${JAVA_HOME}/bin:${PATH}"
ENV GHIDRA_INSTALL_DIR=/goldrush/ghidra_12.1.3_PUBLIC_20260817/ghidra_12.1.3_PUBLIC

# Clone the GitHub repository (replace <username> and <repo> with actual names)
RUN git clone https://github.com/silviadefra/GolDRuSh .

# Install any required packages from requirements.txt
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir "protobuf==5.28.2"
RUN pip install --no-cache-dir -r requirements.txt

