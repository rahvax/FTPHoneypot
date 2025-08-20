build: src/main.c src/ftphoney.c
	gcc -o main src/main.c src/ftphoney.c
run: build
	./main
