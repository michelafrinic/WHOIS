package net.ripe.db.whois.common.rpsl.impl.afrinic;

import org.springframework.stereotype.Component;

/**
 * Created by michel on 7/9/14.
 */
@Component
public class Person extends AbstractObjectType {
    private static final String name = "person";
    private static final String shortName = "pn";

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
                "      A person object contains information about technical or\n" +
                "      administrative contact responsible for the object where it is\n" +
                "      referenced.  Once the object is created, the value of the\n" +
                "      \"person:\" attribute cannot be changed.\n";
    }

    @Override
    public int getId() {
        return 10;
    }
}
