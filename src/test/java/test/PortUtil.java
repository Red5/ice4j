package test;

import java.util.concurrent.atomic.AtomicInteger;

public class PortUtil {

    private final static int PORT_RANGE_START = 49152;

    private final static int PORT_RANGE_MAX = 65536;
    
    private final static AtomicInteger PORT_PROVIDER = new AtomicInteger(49152);

    public final static int getPort() {
        int port = PORT_PROVIDER.getAndIncrement();
        if (port >= PORT_RANGE_MAX) {
            PORT_PROVIDER.set(PORT_RANGE_START);
            port = PORT_PROVIDER.getAndIncrement();
        }
        return port;
    }

}
