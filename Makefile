CFLAGS += -Wall -O2

all: deauth-attack

deauth-attack: main.c
	$(CC) $(CFLAGS) main.c -o deauth-attack

clean:
	rm -f deauth-attack *.o

