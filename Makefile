all: build install

build:
	make -C src
	echo "build done"

install: build
	mkdir -pv target
	mv src/como target
	echo "install done"

clean:
	rm -rvf target 
