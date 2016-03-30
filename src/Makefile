include $(TOPDIR)/rules.mk

TARGET = harrisppp
LIBS = $(LDFLAGS) -L$(STAGING_DIR)/usr/lib -L/usr/lib -lm -lssl -lcrypto -lcrypt -lz 
#CC = gcc
#-lexpat
CFLAGS += -I$(STAGING_DIR)/usr/include -g $(COPTS) -fhonour-copts
#-Wall

.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	echo compile $<
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	echo build $@
	$(CC) $(OBJECTS) -Wall  -o $@ $(LIBS)

clean:
	-rm -f *.o
	-rm -f $(TARGET)