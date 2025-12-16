# =========================================================================
# 面向航空系统的轻量化 PKI 体系 - 项目构建脚本 (Makefile)
# 适用环境: Windows (MinGW) / Linux
# =========================================================================

# -------------------------------------------------------------------------
# 1. 编译器与选项配置
# -------------------------------------------------------------------------
CC = gcc

# CFLAGS: 编译选项
# -Wall -Wextra: 开启所有警告，保持代码严谨
# -I./include: 指定头文件搜索目录
# -D_POSIX_C_SOURCE=200809L: 启用 POSIX 标准支持 (解决 time.h 警告)
CFLAGS = -Wall -Wextra -I./include -D_POSIX_C_SOURCE=200809L

# LDFLAGS: 链接选项
# 链接 OpenSSL 库 (libssl, libcrypto)
LDFLAGS = -lssl -lcrypto

# -------------------------------------------------------------------------
# 2. 目标文件定义 (Windows 下建议显式加上 .exe)
# -------------------------------------------------------------------------
TARGET_DEMO = sm2_implicit_cert_demo.exe
TARGET_TEST = run_tests.exe

# -------------------------------------------------------------------------
# 3. 源文件与对象文件路径
# -------------------------------------------------------------------------
# 核心算法模块 (两个程序共用)
COMMON_SRC = src/sm2_implicit_cert.c
COMMON_OBJ = src/sm2_implicit_cert.o

# 主演示程序
MAIN_SRC = src/main.c
MAIN_OBJ = src/main.o

# 测试套件程序
TEST_SRC = src/test_suite.c
TEST_OBJ = src/test_suite.o

# -------------------------------------------------------------------------
# 4. 伪目标定义
# -------------------------------------------------------------------------
.PHONY: all clean clean_linux run test help

# -------------------------------------------------------------------------
# 5. 构建规则
# -------------------------------------------------------------------------

# 默认目标: 构建主程序
all: $(TARGET_DEMO)

# 通用编译规则: 将 .c 编译为 .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 链接主程序 (Demo)
$(TARGET_DEMO): $(COMMON_OBJ) $(MAIN_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# 链接测试程序 (Test Suite)
$(TARGET_TEST): $(COMMON_OBJ) $(TEST_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# -------------------------------------------------------------------------
# 6. 快捷指令
# -------------------------------------------------------------------------

# 编译并运行演示程序
run: $(TARGET_DEMO)
	@echo.
	@echo [EXEC] Running Demo Application...
	@.\$(TARGET_DEMO)

# 编译并运行测试套件
test: $(TARGET_TEST)
	@echo.
	@echo [EXEC] Running Test Suite...
	@.\$(TARGET_TEST)

# 清理构建产物 (Windows 适配版)
clean:
	@echo [CLEAN] Cleaning build files (Windows)...
	-@del /Q /S src\*.o 2>NUL
	-@del /Q /S *.o 2>NUL
	-@del /Q /S *.exe 2>NUL
	@echo [CLEAN] Done.

# 清理构建产物 (Linux/Mac 适配版 - 供跨平台使用)
clean_linux:
	@echo [CLEAN] Cleaning build files (Linux)...
	rm -f src/*.o *.o *.exe $(TARGET_DEMO) $(TARGET_TEST)
	@echo [CLEAN] Done.

# 显示帮助信息
help:
	@echo.
	@echo Build Options:
	@echo   make all           - Build the main demo program
	@echo   make run           - Build and run the demo
	@echo   make test          - Build and run the test suite
	@echo   make clean         - Clean artifacts (Windows cmd)
	@echo   make clean_linux   - Clean artifacts (Linux bash)
	@echo.