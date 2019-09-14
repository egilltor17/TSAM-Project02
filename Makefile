compile: mkdir 
	g++ -Wall -std=c++11 ./src/scanner.cpp -o ./bin/scanner 

clean: rmdir mkdir compile

rmdir: mkdir
	[ -e ./bin/ ] && rm -r ./bin/

mkdir:
	@[ -d ./bin/ ] || mkdir bin

run: compile
	sudo ./bin/scanner skel.ru.is 4000 4100