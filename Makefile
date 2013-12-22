# spoof makefile
# path C:\GNUWIN32\bin;C:\MinGW\bin;D:\tools\LordPE;C:\BCC5\Bin;D:\tools

CC=gcc
OBJ=sha1.o spoof.o

all: vdfs32g.dll

liborgvdfs32g.a:
	impdef orgVdfs32g.def orgVdfs32g.dll
	dlltool -d orgVdfs32g.def -l liborgvdfs32g.a

%.o: %.c
	$(CC) -O2 $< -c -lshlwapi -Wall

vdfs32g_big.dll: $(OBJ) liborgvdfs32g.a
	$(CC) -O2 sha1.cpp -c -Wall
	dllwrap -def fwdVdfs32g.def -o vdfs32g_big.dll spoof.o sha1.o -lshlwapi -lstdc++ liborgvdfs32g.a -static

vdfs32g.dll: vdfs32g_big.dll
	cp vdfs32g_big.dll vdfs32g.dll
	strip -S vdfs32g.dll
	upx -7 vdfs32g.dll
	yPER vdfs32g.dll /REALIGN_NORMAL /VALIDATE

clean:
	rm -f $(OBJ) liborgvdfs32g.a vdfs32g_big.dll vdfs32g.dll
