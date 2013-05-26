set PROMPT=$$ 
set PATH=C:\MinGW;C:\MinGW\bin

del *.o
del vdfs32g.dll
g++ spoof.cpp -c -lshlwapi -Wall -DDEBUG_FEATURES
g++ sha1.cpp -c -Wall
dllwrap -def fwdVdfs32g.def -o vdfs32g.dll spoof.o sha1.o -lshlwapi -lstdc++ liborgvdfs32g.a -static
pause