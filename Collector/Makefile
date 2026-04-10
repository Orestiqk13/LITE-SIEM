# Ορισμός του compiler
CC = gcc

# Flags για τη μεταγλώττιση (Wall: προειδοποιήσεις, g: debugging, O2: βελτιστοποίηση ταχύτητας)
CFLAGS = -Wall -g -O2

# Το όνομα του εκτελέσιμου αρχείου
TARGET = collector

# Τα αρχεία πηγής
SRCS = collector.c
HEADERS = collector.h

# Η βασική εντολή (γίνεται όταν γράφεις 'make')
all: $(TARGET)

$(TARGET): $(SRCS) $(HEADERS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

# Εντολή για καθαρισμό των αρχείων (γράφεις 'make clean')
clean:
	rm -f $(TARGET)

# Εντολή για εκτέλεση με sudo (γιατί τα logs απαιτούν δικαιώματα)
run: all
	sudo ./$(TARGET)