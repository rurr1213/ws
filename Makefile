include MakefileCommon.inc

# Compiler and flags (using variables from MakefileCommon.inc where possible)
CC = g++
CFLAGS = -g3 -O0 -fsanitize=address $(CXXFLAGS) -I$(SRC_DIR)  # Include the source directory for headers
# Define subdirectory containing source files (if any) - Adjust if necessary
SRC_DIR = .

# Library source files  (Add or remove as needed)
LIB_SRCS = tcp.cpp TcpStringClientServer.cpp WebSocket.cpp
LIB_OBJS = $(LIB_SRCS:.cpp=.o)

# Main program source file
MAIN_SRC = ws.cpp
MAIN_OBJ = $(MAIN_SRC:.cpp=.o)

# Library target (ensure directory exists)
$(LIBDIRGENLIB): $(LIB_OBJS)
	@mkdir -p $(LIBDIR) # Create directory if doesn't exist
	ar rcs $@ $^  # Archive object files into library

# Compile library object files
$(LIB_OBJS): %.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

# Compile main program object file
$(MAIN_OBJ): %.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

all: ws

# Link main program with library
ws: $(MAIN_OBJ) $(LIBDIRGENLIB)
	$(CC) $(CFLAGS) -o $@ $(MAIN_OBJ) -L$(LIBDIR) -l$(GENLIB) `pkg-config --libs openssl` -pthread  # Link with the library


# Clean all compiled files and the library
clean:
	rm -f $(LIB_OBJS) $(MAIN_OBJ) ws $(LIBDIRGENLIB)

