FROM php:7.4-apache

# Install dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    build-essential \
    libsodium-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

 # Build Kage Extension
 COPY . /app_source
 WORKDIR /app_source/c_extension
 RUN mkdir -p build && cd build && \
     cmake .. -DCMAKE_BUILD_TYPE=Release && \
     make -j$(nproc) && \
     cp kage.so $(php-config --extension-dir)/kage.so && \
     docker-php-ext-enable kage

 # Configure Apache
 RUN a2enmod rewrite
 RUN echo "DirectoryIndex index.kage index.php" >> /etc/apache2/apache2.conf
 RUN echo "<FilesMatch \\.kage$>\n  SetHandler application/x-httpd-php\n</FilesMatch>" >> /etc/apache2/apache2.conf
 RUN echo "PassEnv KAGE_ENCRYPTION_KEY" >> /etc/apache2/apache2.conf

# Setup working dir
WORKDIR /var/www/html

# The actual encrypted files will be mounted via docker-compose for dev, 
# but for a production image you would COPY them here.
EXPOSE 80
