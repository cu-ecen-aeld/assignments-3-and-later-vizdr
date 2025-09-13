CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -g -Wall -Werror
SRCDIR = .
SRC = aesdsocket.c
TARGET = aesdsocket
LDFLAGS ?= -pthread
OBJS := $(SRC:.c=.o)

all: $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) $(OBJS) -o $(TARGET) $(LDFLAGS)

%.o : $(SRCDIR)/%.c
	@if [ ! -f $< ]; then \
	echo "Error: Source file $< not found"; \
	exit 1; \
	fi
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) *.o *.elf *.map
