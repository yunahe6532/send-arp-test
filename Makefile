all: send-arp-test

send-arp-test: main.cpp
	gcc -g -o send-arp-test main.cpp -lpcap

main.o: 
	gcc -g -c -o main.o main.cpp

clean:
	rm -f send-arp-test
	rm -f *.o
