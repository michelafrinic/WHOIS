package net.ripe.db.whois.common.rpsl.impl.afrinic;

import org.springframework.stereotype.Component;

/**
 * Created by michel on 7/9/14.
 */
@Component
public class ASSet extends AbstractObjectType {
    private static final String name = "as-set";
    private static final String shortName = "as";

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
        "      An as-set object defines a set of aut-num objects. The\n" +
        "      attributes of the as-set class are shown in Figure 1.2.2.  The\n" +
        "      \"as-set:\" attribute defines the name of the set. It is an RPSL\n" +
        "      name that starts with \"as-\". The \"members:\" attribute lists the\n" +
        "      members of the set.  The \"members:\" attribute is a list of AS\n" +
        "      numbers, or other as-set names.\n";
    }

    @Override
    public int getId() {
        return 1;
    }
}
