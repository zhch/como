all: build install

build:
	make -C src
	echo "build done"

install: build
	mkdir -pv target/lib
	cp -rv lib/glib/lib target/lib/glib

	mkdir -pv target
	cp -v script/como.sh target
	chmod +x target/como.sh	

	mkdir -pv target
	mv src/como target
	echo "install done"

clean:
	rm -rvf target 
