package test;

import java.util.concurrent.atomic.AtomicInteger;

public class PortUtil {

    private final static AtomicInteger port = new AtomicInteger(50000);

    public final static int getPort() {
        return port.getAndIncrement();
    }

}
