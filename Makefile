LIBS_DIR=libs
CC=gcc
SRC=$(wildcard $(LIBS_DIR)/*.c)
OBJ=$(patsubst %.c,%.o,$(SRC))
SO=$(patsubst %.c,%.so,$(SRC))

all: $(SO)

$(LIBS_DIR)/%.so: $(LIBS_DIR)/%.o
	$(CC) -shared -o $@ $<

$(LIBS_DIR)/%.o: $(LIBS_DIR)/%.c $(LIBS_DIR)/%.h
	$(CC) -c -Wall -o $@ $<

clean:
	rm -f $(LIBS_DIR)/*.o $(LIBS_DIR)/*.so

.PHONY: clean