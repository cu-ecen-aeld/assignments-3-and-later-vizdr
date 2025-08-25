SRC := writer.c
OBJFS := $(SRC:.c=.o)

CC := $(CROSS_COMPILE)gcc

writer : $(OBJFS)
	$(CC) $(CFLAGS) $(INCLUDES) $(OBJFS) -o writer $(LDFLAGS)

clean:
	-rm -f *.o writer *.elf *.map
