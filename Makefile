CC = gcc
IDIR = c-libs
CFLAGS = -Wall -I$(IDIR)/
LDLIBS = -lcurl -lexpat -lpcre2-8
OBJS = list.o map.o

xml_helper_dev: xml_helper_dev.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ $< $(OBJS) $(LDLIBS)

%.o: $(IDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@ 

clean:
	rm -f *.o xml_helper_dev
