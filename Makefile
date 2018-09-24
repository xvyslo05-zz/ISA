CC = gcc
CFLAGS = -Wall -pedantic -pthread
LIBS = -lpcap


TARGET = dns-export

all: $(TARGET)

$(TARGET): $(TARGET).c
	$(CC) $(TARGET).c $(CFLAGS) -o $(TARGET) $(LIBS)

clean:
	$(RM) $(TARGET)