package net.afrinic.db.whois.common.rpsl.impl;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.rpsl.IObjectType;
import net.ripe.db.whois.common.rpsl.IObjectTypeFactory;
import net.ripe.db.whois.common.rpsl.impl.*;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.Collection;
import java.util.List;

/**
 * Created by michel on 7/15/14.
 */
public class AfrinicObjectTypeFactoryDeepSearchTest {
    private IObjectType inetNumObjectType;
    private IObjectType inet6NumObjectType;
    private IObjectType roleObjectType;
    private IObjectType role3;
    private IObjectType role4;

    private IObjectTypeFactory afrinicObjectTypeFactory;

    @Before
    public void init() {
        inetNumObjectType = new InetNum();
        inet6NumObjectType = new Inet6Num();
        roleObjectType = new Role();
        role3 = new Role3();
        role4 = new Role4();

        List<IObjectType> objectTypeList = Lists.newArrayList(role3, inetNumObjectType, roleObjectType, inet6NumObjectType, role4);
        afrinicObjectTypeFactory = new AfrinicObjectTypeFactory(objectTypeList);
    }

    @Test
    public void testAfrinicObjectFactory() {
        IObjectType objectType = afrinicObjectTypeFactory.get(Role.class);
        Assert.assertEquals(role4, objectType);

        objectType = afrinicObjectTypeFactory.get(Role3.class);
        Assert.assertEquals(role4, objectType);

        objectType = afrinicObjectTypeFactory.get(Role2.class);
        Assert.assertEquals(role4, objectType);
    }

    class Role2 extends Role {
        @Override
        public String getName() {
            return "this is role2 !!";
        }

        @Override
        public String getShortName() {
            return "role2";
        }

        @Override
        public boolean isSet() {
            return false;
        }

        @Override
        public String getDocumentation() {
            return "role2 blah blah";
        }

        @Override
        public int getId() {
            return 123;
        }
    }

    class Role3 extends Role2 {
        @Override
        public String getName() {
            return "this is role3 !!";
        }

        @Override
        public String getShortName() {
            return "role3";
        }

        @Override
        public boolean isSet() {
            return false;
        }

        @Override
        public String getDocumentation() {
            return "role3 blah blah";
        }

        @Override
        public int getId() {
            return 1234;
        }
    }

    class Role4 extends Role3 {
        @Override
        public String getName() {
            return "this is role4 !!";
        }

        @Override
        public String getShortName() {
            return "role4";
        }

        @Override
        public boolean isSet() {
            return false;
        }

        @Override
        public String getDocumentation() {
            return "role4 blah blah";
        }

        @Override
        public int getId() {
            return 12345;
        }
    }
}