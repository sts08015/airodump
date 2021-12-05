CC = g++
LDLIBS = -lpcap

all: airodump

airodump: mac.o main.o
	$(CC) $^ -o $@ $(LDLIBS)

clean:
	@rm -f ./airodump *.o