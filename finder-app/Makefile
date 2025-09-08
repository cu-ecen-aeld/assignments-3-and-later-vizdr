TARGET := writer
SRC := writer.c
OBJFS := $(SRC:.c=.o)

CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -Wall -Wextra -g

all: $(TARGET)

$(TARGET) : $(OBJFS)
	$(CC) $(CFLAGS) $(INCLUDES) $(OBJFS) -o $(TARGET) $(LDFLAGS)

clean:
	-rm -f *.o $(TARGET) *.elf *.map
