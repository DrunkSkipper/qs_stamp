CXXFLAGS =-std=c++11 -pipe -O2
LDFLAGS = -lsodium
quicksand:  quicksand.o main.o
	g++ -I. main.o quicksand.o -o quicksand $(LDFLAGS)

main.cpp:
	g++ $(CXX_FLAGS) main.cpp -o main.o

quicksand.cpp:
	g++ $(CXX_FLAGS) quicksand.cpp -o quicksand.o


clean:
	rm -f *.o
	rm -f quicksand
	rm -f *.so

lib:
	g++ -shared -fPIC -std=c++11 -pipe -O2 quicksand.cpp -o libquicksand.so
