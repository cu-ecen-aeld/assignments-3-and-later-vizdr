SRC := writer.c
OBJFS := $(SRC:.c=.o)

CC := $(CROSS_COMPILE)gcc

all: writer

writer : $(OBJFS)
	$(CC) $(CFLAGS) $(INCLUDES) $(OBJFS) -o writer $(LDFLAGS)

%.o : %.c
    $(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	-rm -f *.o writer *.elf *.map
