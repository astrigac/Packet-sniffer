PRJ=ipk-project_2

NAME=sniffer
CC=gcc
CFLAGS=-Wall -Wextra -pedantic -lm -fcommon

run: sniffer.c
	${CC} ${CFLAGS} sniffer.c -lpcap -o ${NAME} 

.PHONY: clean
clean:
	rm -f sniffer
	rm -f *.in