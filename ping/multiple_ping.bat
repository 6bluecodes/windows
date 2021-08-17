:: This is bat file to ping multiple machines using batch script.
:: List of servers are kept in computers.txt file



@Echo Off
:: Ping multiple servers
setlocal
FOR /F %%c IN (C:\temp\computers.txt) Do (
Echo Ping server %%c >> C:\temp\pingout.txt
Ping -a -f -n 1 -l 1 %%c >> C:\temp\pingout.txt
)
