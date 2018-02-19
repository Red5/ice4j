# NIO Configuration
The following ice4j adjustments are available in the NIO version via environmental / system properties.

## Send buffer
Configuration of the send buffer is handled via the `SO_SNDBUF` property. The default is 1500 and any target amount should take MTU size ~1500 into account.

## Receive buffer
Configuration of the receive buffer is handled via the `SO_RCVBUF` property. The default is 1500 and any target amount should take MTU size ~1500 into account.

## I/O thread priority
Setting the I/O thread priority is handled via the `IO_THREAD_PRIORITY` property. The default priority is 6 and the maximum availabe in Java is 10.

## NIO selector sleep milliseconds
Providing adequate time between NIO selector checks is handled via the `NIO_SELECTOR_SLEEP_MS` property. The default sleep time between checks is 10 milliseconds.

# Server Startup
To add the options to your Red5 / Red5 Pro server startup, update the `JAVA_OPTS` line like so:
```
export JAVA_OPTS="$SECURITY_OPTS $JAVA_OPTS $JVM_OPTS $TOMCAT_OPTS $NATIVE -DSO_RCVBUF=3000 -DIO_THREAD_PRIORITY=6 -DNIO_SELECTOR_SLEEP_MS=10"
```
