SHELLCODES:=$(wildcard *.cpp) $(wildcard *.c) $(wildcard *.S)

OS:=$(patsubst %.cpp,out/%.o,$(patsubst %.S,out/%.o,$(patsubst %.c,out/%.o,$(SHELLCODES))))

ELFS:=$(patsubst %.o,%.elf,$(OS))
BINS:=$(patsubst %.elf,%.bin,$(ELFS))
MAPS:=$(patsubst %.elf,%.map,$(ELFS))
ASMS:=$(patsubst %.elf,%.s,$(ELFS))

# Use 'make IMAGE_BASE=<base_address>' to enforce base address of generated code.

LDFLAGS:=-Bstatic -x -X
ARCH=x86


CFLAGS:=-Wall -Wno-unused-function -static -nostdlib -nodefaultlibs -fno-common -fno-strict-aliasing -fno-toplevel-reorder -fPIC -fno-builtin
OBJDUMP_FLAGS:=
IMAGE_BASE:= 0xffff000880000000

CFLAGS+= -Os

LDSCRIPT:= arm-ld.script
PREFIX?=<PUT HERE YOUR GCC LINARY TOOLCHAIN PATH>/gcc-linaro-7.5.0-2019.12-i686_aarch64-linux-gnu/bin/aarch64-linux-gnu-

ifneq (,$(IMAGE_BASE))
	LDFLAGS+=-Ttext=$(IMAGE_BASE)
endif

AS:=$(PREFIX)as
CC:=$(PREFIX)gcc
CXX:=$(PREFIX)g++
LD:=$(PREFIX)ld
OBJCOPY:=$(PREFIX)objcopy
OBJDUMP:=$(PREFIX)objdump
CXXFLAGS:=$(CFLAGS)
CFLAGS+= -std=c99

all: $(BINS)

out/%.elf: out/%.o $(LDSCRIPT)
	@$(LD) $(LDFLAGS) -Map $(patsubst %.elf,%.map,$@) -T $(LDSCRIPT) $< -o $@
	@#@$(OBJDUMP) $(OBJDUMP_FLAGS) -d $@

out/%.bin: out/%.elf
	@$(OBJCOPY) -O binary -j .text -j .bss --set-section-flags .bss=alloc,load,contents $< $@

out/%.o: %.c Makefile
	@mkdir -p out
	@$(CC) $(CFLAGS) -c -o $@ $<

out/%.s: %.c Makefile
	@mkdir -p out
	@$(CC) $(CFLAGS) -S -c -o $@ $<

out/%.o: %.cpp Makefile
	@mkdir -p out
	@$(CXX) $(CXXFLAGS) -c -o $@ $<

out/%.o: %.s Makefile
	@$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(BINS) $(ELFS) $(OS) $(MAPS)

execute: out/shellcode.bin
	cd .. && source env/bin/activate &&\
	../p6bl.py execute 0xffff000880000000 shellcode/out/shellcode.bin &&\
	cd -

.PHONY: all clean
.PRECIOUS: out/%.elf out/%.o

