CC := /home/w4118/utils/arm-2013.11/bin/arm-none-linux-gnueabi-gcc
LD := /home/w4118/utils/arm-2013.11/bin/arm-none-linux-gnueabi-gcc
ADB := /home/w4118/utils/android-sdk-linux/platform-tools/adb
CFLAGS := -g -Wall -Werror -static
INCLUDE = -I. -I../flo-kernel/usr/include -I../flo-kernel/include -I../flo-kernel/arch/arm/include
LDFLAGS := -static $(INCLUDE)

OBJECTS := vm_inspector.o

all: vm_inspector
	$(ADB) push vm_inspector /data/misc
	$(ADB) shell /data/misc/vm_inspector

: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJECTS)

%.o: %.c
	$(CC) $(CFLAGS) -c $^

clean:
	rm -f vm_inspector
	rm -f vm_inspector.o

.PHONY: clean
