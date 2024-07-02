LDLIBS = -lpcap

# Directories
SRC_DIR = .
MAC_DIR = ./mac
IP_DIR = ./ip
UTIL_DIR = ./util
SPOOF_DIR = ./spoof
ARP_DIR = ./arp

# Include directories
INCLUDES = -I$(MAC_DIR) -I$(IP_DIR) -I$(UTIL_DIR) -I$(SPOOF_DIR) -I$(ARP_DIR)

# Source files
SOURCES = $(SRC_DIR)/main.cpp \
          $(MAC_DIR)/mac.cpp $(MAC_DIR)/ethhdr.cpp \
          $(IP_DIR)/ip.cpp $(IP_DIR)/iphdr.cpp \
          $(UTIL_DIR)/util.cpp \
          $(SPOOF_DIR)/spoof.cpp \
          $(ARP_DIR)/arphdr.cpp

# Object files
OBJECTS = main.o \
          mac.o ethhdr.o \
          ip.o iphdr.o \
          util.o \
          spoof.o \
          arphdr.o

# Header files
HEADERS = $(MAC_DIR)/mac.h $(MAC_DIR)/ethhdr.h \
          $(IP_DIR)/ip.h $(IP_DIR)/iphdr.h \
          $(UTIL_DIR)/util.h \
          $(SPOOF_DIR)/spoof.h \
          $(ARP_DIR)/arphdr.h

# Targets
all: arp-spoof

# Compilation rules
main.o: $(SRC_DIR)/main.cpp $(HEADERS)
	$(COMPILE.cpp) $(INCLUDES) $(SRC_DIR)/main.cpp -o main.o

mac.o: $(MAC_DIR)/mac.cpp $(MAC_DIR)/mac.h
	$(COMPILE.cpp) $(INCLUDES) $(MAC_DIR)/mac.cpp -o mac.o

ethhdr.o: $(MAC_DIR)/ethhdr.cpp $(MAC_DIR)/ethhdr.h $(MAC_DIR)/mac.h
	$(COMPILE.cpp) $(INCLUDES) $(MAC_DIR)/ethhdr.cpp -o ethhdr.o

ip.o: $(IP_DIR)/ip.cpp $(IP_DIR)/ip.h
	$(COMPILE.cpp) $(INCLUDES) $(IP_DIR)/ip.cpp -o ip.o

iphdr.o: $(IP_DIR)/iphdr.cpp $(IP_DIR)/iphdr.h
	$(COMPILE.cpp) $(INCLUDES) $(IP_DIR)/iphdr.cpp -o iphdr.o

util.o: $(UTIL_DIR)/util.cpp $(UTIL_DIR)/util.h
	$(COMPILE.cpp) $(INCLUDES) $(UTIL_DIR)/util.cpp -o util.o

spoof.o: $(SPOOF_DIR)/spoof.cpp $(SPOOF_DIR)/spoof.h
	$(COMPILE.cpp) $(INCLUDES) $(SPOOF_DIR)/spoof.cpp -o spoof.o

arphdr.o: $(ARP_DIR)/arphdr.cpp $(ARP_DIR)/arphdr.h $(MAC_DIR)/mac.h $(IP_DIR)/ip.h
	$(COMPILE.cpp) $(INCLUDES) $(ARP_DIR)/arphdr.cpp -o arphdr.o

# Linking
arp-spoof: $(OBJECTS)
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

# Clean up
clean:
	rm -f arp-spoof *.o
