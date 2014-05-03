package net.ripe.db.whois.api.whois;

import net.ripe.db.whois.query.domain.ResponseHandler;

import java.net.InetAddress;

abstract class ApiResponseHandler implements ResponseHandler {
    @Override
    public String getApi() {
        return "API";
    }

    @Override
    public InetAddress getRemoteAddress() {
        return null;
    }
}
