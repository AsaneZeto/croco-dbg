CFLAGS = -Wextra -Wall -Wno-unused-parameter -D_GNU_SOURCE -g -MMD -Iinclude -Iext/linenoise 

BUILDDIR ?= build
CURDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
SHELL_HACK := $(shell mkdir -p $(BUILDDIR))

CSRCS = $(shell find ./src -name '*.c')
CSRCS += $(shell find ./ext/linenoise -name 'linenoise.c')
EXPSRCS = $(shell find ./examples -name '*.c')
EXP = $(EXPSRCS:%.c=%)
_COBJ = $(notdir $(CSRCS))
COBJ = $(_COBJ:%.c=$(BUILDDIR)/%.o)
TARGET = tinydbg


vpath %.c $(sort $(dir $(CSRCS)))

.PHONY: all clean echo

all: $(TARGET) $(EXP)

$(BUILDDIR)/%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@ 

$(TARGET): $(COBJ)
	$(CC) $(CFLAGS) $^ -o $@

$(EXP): $(EXPSRCS)
	$(CC) -g $< -o $@

clean:
	$(RM) $(COBJ)
	$(RM) $(TARGET)
	$(RM) $(BUILDDIR)/*.o $(BUILDDIR)/*.d
	$(RM) $(EXP)

echo:
	echo $(COBJ)