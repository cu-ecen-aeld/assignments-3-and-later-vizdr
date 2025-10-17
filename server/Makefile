# Specify the cross-compile executable
CROSS_COMPILE ?=

CC ?= $(CROSS_COMPILE)gcc
$(info input: $(CROSS_COMPILE))
$(info Using compiler: $(CC))
CFLAGS ?= -g -Wall -Werror
# adjust path as needed
CFLAGS += -I$(SRCDIR)
SRCDIR = .
SRC = aesdsocket.c
INCLUDES = -I../aesd_char_driver
TARGET = aesdsocket
LDFLAGS ?= -pthread
OBJS := $(SRC:.c=.o)

# Char device flag: 1 enable, 0 disable
CFLAGS += -DUSE_AESD_CHAR_DEVICE=1

all: $(TARGET)

# Building the Executable ($(TARGET)):
$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $(OBJS) -o $(TARGET) $(LDFLAGS)

# $^ represents all prerequisites (the object files).
# $@ represents the target name (the executable).



# Compiling Source Files (%.o: %.c):
# This is an implicit rule that tells make how to compile any .c file into a .o file.
# $< represents the first prerequisite (the .c file).
%.o : $(SRCDIR)/%.c
	@if [ ! -f $< ]; then \
	echo "Error: Source file $< not found"; \
	exit 1; \
	fi
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) *.o *.elf *.map
