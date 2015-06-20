
all: sortidx checksort


sortidx:
	gcc -O3 sortidx.c -o sortidx

checksort:
	gcc -O3 checksort.c -o sortidx

clean:
	rm -f sortidx
	rm -f checksort