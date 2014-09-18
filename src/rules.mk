ifeq "$(build)" "debug"
CFLAGS += -ggdb
else ifeq "$(build)" "release"
    CFLAGS += -O2 -fomit-frame-pointer
else
    $(error unknown build setting: '$(build)')
endif
