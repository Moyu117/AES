# Makefile 示例

CC      = gcc
CFLAGS  = -Wall -O2   # 可根据需要加调试 -g
LDLIBS  =
TARGETS = aes_app test_cipher test_keyexpansion test_mode

# 让 make all 时同时生成所有目标
.PHONY: all clean
all: $(TARGETS)

# 1. main - 链接 main.c, aes.c, modes.c
aes_app: main.o aes.o modes.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# 2. test_cipher - 链接 test_cipher.c + aes.c
test_cipher: test_cipher.o aes.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# 3. test_keyexpansion - 链接 test_keyexpansion.c + aes.c
test_keyexpansion: test_keyexpansion.o aes.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# 4. test_mode - 链接 mode_test.c + aes.c + modes.c
test_mode: mode_test.o aes.o modes.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# 通用的 .c -> .o 规则
%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o $(TARGETS)
