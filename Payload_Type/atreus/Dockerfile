FROM itsafeaturemythic/mythic_python_base:latest
RUN apt-get update && apt-get install -y build-essential mingw-w64
RUN pip3 install donut-shellcode
WORKDIR /Mythic/
# Copier le code local dans le container
COPY . /Mythic/
CMD ["python3", "main.py"]
