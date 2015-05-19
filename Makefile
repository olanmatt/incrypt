CXX ?= g++
CC ?= gcc
SRCDIR := src
HEADERDIR := include
BUILDDIR := build
TARGET := bin/incrypt

SRCEXT := c
SOURCES := $(shell find $(SRCDIR) -type f -name "*.$(SRCEXT)")
HEADERS := $(shell find $(HEADERDIR) -type f -name "*.h")
OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.$(SRCEXT)=.o))
CFLAGS := -g -Wall
LIB := -lcrypto
INC := -I include

all: $(TARGET)

$(TARGET): $(OBJECTS)
	@echo " Linking..."
	$(CC) $^ -o $(TARGET) $(LIB)

$(BUILDDIR)/%.o: $(SRCDIR)/%.$(SRCEXT)
	@mkdir -p $(BUILDDIR)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

.PHONY: clean style astyle cpplint

test: $(TARGET)
	mkdir -p ./test
	curl -o ./test/image.tiff http://sipi.usc.edu/database/download.php?vol=misc&img=4.1.07
	md5sum ./test/* > ./md5sum.txt
	./bin/incrypt -k 0123456789012345 -f ./test/image.tiff
	./bin/incrypt -k 0123456789012345 -f ./test/image.tiff -d
	md5sum -c md5sum.txt

style: astyle cpplint

astyle:
	@astyle --style=allman --suffix=none $(SOURCES) $(HEADERS)

cpplint:
	@cpplint  $(CPPLINT_EXTRA) \
		--filter=-whitespace/line_length,-whitespace/braces,-readability/alt_tokens,-whitespace/newline\
		$(SOURCES) $(HEADERS) $(TESTSOURCES)

clean:
	@echo " Cleaning...";
	$(RM) -r $(BUILDDIR) $(TARGET)
