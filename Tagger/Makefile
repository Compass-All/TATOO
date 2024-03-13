CC = riscv64-unknown-linux-gnu-gcc
CFLAGS = -Wall -Wextra

all: tagger

tagger: copy.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f tagger
