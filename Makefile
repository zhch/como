all: build install

build:
	make -C src
	echo "build done"

install: build
	mkdir -p target/lib
	cp -r lib/glib/lib target/lib/glib

	mkdir -p target
	cp -v script/como.sh target
	chmod +x target/como.sh	

	mkdir -p target
	mv src/como target
	echo "install done"

clean:
	rm -rvf target 
