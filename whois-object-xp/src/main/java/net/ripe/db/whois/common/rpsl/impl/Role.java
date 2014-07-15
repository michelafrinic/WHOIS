package net.ripe.db.whois.common.rpsl.impl;

import org.springframework.stereotype.Component;

/**
 * Created by michel on 7/9/14.
 */
@Component
public class Role extends AbstractObjectType {
    private static final String name = "role";
    private static final String shortName = "ro";

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
                "      The role class is similar to the person class.  However, instead\n" +
                "      of describing a human being, it describes a role performed by\n" +
                "      one or more human beings.  Examples include help desks, network\n" +
                "      monitoring centres, system administrators, etc.  A role object\n" +
                "      is particularly useful since often a person performing a role\n" +
                "      may change; however the role itself remains. The \"nic-hdl:\"\n" +
                "      attributes of the person and role classes share the same name\n" +
                "      space. Once the object is created, the value of the \"role:\"\n" +
                "      attribute cannot be changed.\n";
    }

    @Override
    public int getId() {
        return 11;
    }
}
