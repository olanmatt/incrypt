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

style: astyle cpplint

astyle:
	@astyle --style=allman --suffix=none $(SOURCES) $(HEADERS)

cpplint:
	@cpplint  $(CPPLINT_EXTRA) \
		--filter=-whitespace/line_length,-whitespace/braces,-whitespace/newline\
		$(SOURCES) $(HEADERS) $(TESTSOURCES)

clean:
	@echo " Cleaning...";
	$(RM) -r $(BUILDDIR) $(TARGET)
