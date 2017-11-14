SRCDIR		:= ../../src
OBJDIR		:= obj
BINDIR		:= bin

MKDIR		:= mkdir -p
RM		:= rm -rf

CXX		:= g++
CXX_FLAGS	:= -std=gnu++11 -c -MMD -MP

LD		:= g++
LD_FLAGS	:= 

PKGS		:= openssl

CXX_FLAGS	+= \
		-I../../external/openssl/include \
		-include ../../src/stdafx.hpp

LD_FLAGS	+= \
		../../external/openssl/libssl.a \
		../../external/openssl/libcrypto.a \
		-pthread \
		-ldl

CXX_FLAGS	+= -g -O0

#
#
#
SRCS		:= $(wildcard $(SRCDIR)/*.cpp)
OBJS		:= $(patsubst $(SRCDIR)/%.cpp, $(OBJDIR)/%.o, $(SRCS))

TARGET		:= $(BINDIR)/ssltest

$(TARGET): $(OBJS)
	@$(MKDIR) $(dir $@)
	$(LD) -o $@ $+ $(LD_FLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	@$(MKDIR) $(dir $@)
	$(CXX) $(CXX_FLAGS) -o $@ $<

-include $(patsubst %.o, %.d, $(OBJS))

#
#
#
.PHONY: run
run: $(TARGET)
	$(TARGET)

.PHONY: debug
debug: $(TARGET)
	gdb -q $(TARGET)

.PHONY: clean
clean:
	$(RM) $(OBJDIR) $(BINDIR)
