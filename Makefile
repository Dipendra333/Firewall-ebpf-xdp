CLANG ?= clang
CC ?= gcc

BPF_CFLAGS = \
	-target bpf \
	-I/usr/include/aarch64-linux-gnu \
	-g \
	-O2

USER_CFLAGS = -g -O2

all: firewall.bpf.o user_app

firewall.bpf.o: firewall.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

user_app: user_app.c
	$(CC) $(USER_CFLAGS) $< -o $@ -lbpf -lelf

clean:
	rm -f firewall.bpf.o user_app
