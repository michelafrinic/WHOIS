package net.ripe.db.whois.query.domain;

import net.ripe.db.whois.common.domain.ResponseObject;

import java.net.InetAddress;

public interface ResponseHandler {
    String getApi();
    InetAddress getRemoteAddress();

    void handle(ResponseObject responseObject);
}
