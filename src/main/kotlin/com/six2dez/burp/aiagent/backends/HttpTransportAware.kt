package com.six2dez.burp.aiagent.backends

import com.six2dez.burp.aiagent.backends.http.MontoyaHttpTransport

/**
 * A backend whose health check performs HTTP I/O and must therefore use Burp's HTTP stack.
 *
 * BUG-69-01: health-check traffic has to go through [MontoyaHttpTransport] so Burp's upstream
 * proxy, SOCKS settings and certificate store participate; a direct socket would silently bypass
 * them. [BackendRegistry] owns the transport and re-applies it to every implementing instance on
 * each [BackendRegistry.reload] (the Settings save path recreates every backend), so the injection
 * survives a reload instead of being lost after the first save.
 */
interface HttpTransportAware {
    fun setHealthCheckTransport(transport: MontoyaHttpTransport)

    fun healthCheckTransport(): MontoyaHttpTransport?
}
