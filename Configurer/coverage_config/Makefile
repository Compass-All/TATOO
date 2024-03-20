CC = riscv64-unknown-linux-gnu-gcc
CFLAGS = -Wall -Wextra

SOURCES := $(wildcard *.c)

OBJECTS := $(SOURCES:.c=.o)

TARGET = phmonconfig

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)


	
	



