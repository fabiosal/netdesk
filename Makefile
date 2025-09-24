.DEFAULT_GOAL := run

netdesk: main.c
	gcc main.c -o netdesk

clean:
	rm netdesk

run: netdesk
	sudo ./netdesk
