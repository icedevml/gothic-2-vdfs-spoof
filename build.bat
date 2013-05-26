set PROMPT=$$ 
set PATH=C:\MinGW;C:\MinGW\bin

del *.o
del vdfs32g.dll
g++ -O2 spoof.cpp -c -lshlwapi -Wall
g++ -O2 sha1.cpp -c -Wall
dllwrap -def fwdVdfs32g.def -o vdfs32g.dll spoof.o sha1.o -lshlwapi -lstdc++ liborgvdfs32g.a -static
strip -S vdfs32g.dll
C:\WINDOWS\system32\upx -7 vdfs32g.dll
D:\tools\LordPE\yPER.exe vdfs32g.dll /REALIGN_NORMAL /VALIDATE
pause