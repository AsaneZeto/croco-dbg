CFLAGS = -Wextra -Wall -D_GNU_SOURCE -g -MMD -Iinclude -Iext/linenoise 

BUILDDIR ?= build
CURDIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
SHELL_HACK := $(shell mkdir -p $(BUILDDIR))

CSRCS = $(shell find ./src -name '*.c')
CSRCS += $(shell find ./ext/linenoise -name 'linenoise.c')
_COBJ = $(notdir $(CSRCS))
COBJ = $(_COBJ:%.c=$(BUILDDIR)/%.o)
TARGET = tinydbg


vpath %.c $(sort $(dir $(CSRCS)))

.PHONY: all clean echo

all: $(TARGET)

$(BUILDDIR)/%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@ 

$(TARGET): $(COBJ)
	$(CC) $(CFLAGS) $^ -o $@ 

clean:
	$(RM) $(COBJ)
	$(RM) $(TARGET)
	$(RM) $(BUILD_DIR)/*.o