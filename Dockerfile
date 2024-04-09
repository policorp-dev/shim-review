FROM debian:bookworm

# Add the Bookworm repository to sources.list with both deb and deb-src entries
RUN echo "deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian/ bookworm main" > /etc/apt/sources.list.d/bookworm.list && \
    echo "deb-src [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian/ bookworm main" >> /etc/apt/sources.list.d/bookworm.list

# Update package lists and install build dependencies
#
RUN apt-get update -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential devscripts  fakeroot software-properties-common git-buildpackage dos2unix
RUN apt-get build-dep -y shim

# Set the working directory

RUN git clone --recursive -b 15.8 https://github.com/rhboot/shim.git shim-policorp
WORKDIR /shim-policorp

COPY policorp.der /shim-policorp/
COPY sbat.policorp.csv /shim-policorp/data/
COPY shimx64.efi /

# Build the shim package
RUN make VENDOR_CERT_FILE=policorp.der

# Validate built shimx64.efi file
RUN hexdump -Cv /shim-policorp/shimx64.efi > build
RUN hexdump -Cv /shimx64.efi > orig
RUN diff -u orig build

