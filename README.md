# TSAM - Assignment 02 - Ports!

### Compiling the code
Run `make` or
`g++ -Wall -std=c++11 ./src/scanner.cpp -o ./bin/scanner` \
in a terminal in the root directory of the assignment.

### Running the scanner
Run `./bin/scanner <ip host> <low ip port number> <hight ip port number>`  \
to start the scanner with your desired port interval.

Or `make run` to run the scanner on skel.ru.is 4000 4100


_The host can be an IP address or a DNS host name._ (todo: look at)

### High level explanation
Start the scanner and it will send a request to all the udp ports on the host in the desired range. Then it will send further messages to the evil and checksum port extracting their secrets, sending them to th oracle to get the correct sequence and executing it.
