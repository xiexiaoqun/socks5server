package socks5.socks5server.server.listener;

import socks5.socks5server.server.io.Pipe;

/**
 * The class <code></code>
 *
 * @author Youchao Feng
 * @version 1.0
 * @date Mar 03,2016 7:24 PM
 */
public interface PipeInitializer {

    Pipe initialize(Pipe pipe);

}
