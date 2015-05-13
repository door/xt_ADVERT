all:
	$(MAKE) -C src

clean:
	$(MAKE) -C src clean

install:
	$(MAKE) -C src install
	@echo "do not forget to run 'depmod'"
