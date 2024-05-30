PRJ=ipk-project_2

NAME=ipk-sniffer
CC=gcc
CFLAGS=-Wall -Wextra -pedantic -lm -fcommon

run: ipk-sniffer.c
	${CC} ${CFLAGS} ipk-sniffer.c -lpcap -o ${NAME} 

.PHONY: clean
clean:
	rm -f ipk-sniffer
	rm -f *.in