# 编译器设置
CC = gcc
CFLAGS = -Wall -Wextra -I./include
LDFLAGS = 

# 目标文件
TARGET = sm2_implicit_cert_demo

# 源文件
SRCS = src/sm2_implicit_cert.c src/main.c

# 中间文件
OBJS = $(SRCS:.c=.o)

# 默认目标
all: $(TARGET)

# 编译目标文件
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 链接可执行文件
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# 清理中间文件和可执行文件
clean:
	rm -f $(OBJS) $(TARGET)

# 运行程序
run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run