package net.ripe.db.whois.common.rpsl.impl.afrinic;

import org.springframework.stereotype.Component;

/**
 * Created by michel on 7/9/14.
 */
@Component
public class KeyCert extends AbstractObjectType {
    private static final String name = "key-cert";
    private static final String shortName = "kc";

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getShortName() {
        return shortName;
    }

    @Override
    public boolean isSet() {
        return false;
    }

    @Override
    public String getDocumentation() {
        return "" +
                "      A key-cert object is a database public key certificate \n" +
                "      that is stored on the server and may be used with a mntner \n" +
                "      object for authentication when performing updates. \n" +
                "      Currently only PGP/GnuPG keys are supported.\n";
    }

    @Override
    public int getId() {
        return 7;
    }
}
